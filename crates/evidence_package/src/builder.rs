// Package builder - assembles evidence packages from dig_index, burns, etc.

use crate::{PackageError, PackageResult, PACKAGE_FORMAT_VERSION};
use crate::manifest::*;
use dig_index::{DigIndexEntry, DigIndexQuery};
use dig_mem::DigFile;
use compliance_index::burn::ComplianceBurn;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::PathBuf;

/// Builder for evidence packages
pub struct PackageBuilder {
    tenant_id: String,
    scope: PackageScope,
    created_by: Option<String>,
    
    // Paths
    dig_index_db: Option<String>,
    dig_storage_root: Option<String>,
    burn_storage_root: Option<String>,
    
    // Collected artifacts
    artifacts: Vec<PackageArtifact>,
    
    // Metadata
    metadata: HashMap<String, String>,
}

impl PackageBuilder {
    pub fn new(tenant_id: String, scope: PackageScope) -> Self {
        Self {
            tenant_id,
            scope,
            created_by: None,
            dig_index_db: None,
            dig_storage_root: None,
            burn_storage_root: None,
            artifacts: Vec::new(),
            metadata: HashMap::new(),
        }
    }
    
    pub fn created_by(mut self, did: String) -> Self {
        self.created_by = Some(did);
        self
    }
    
    pub fn dig_index_db(mut self, path: String) -> Self {
        self.dig_index_db = Some(path);
        self
    }
    
    pub fn dig_storage_root(mut self, path: String) -> Self {
        self.dig_storage_root = Some(path);
        self
    }
    
    pub fn burn_storage_root(mut self, path: String) -> Self {
        self.burn_storage_root = Some(path);
        self
    }
    
    pub fn metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Build the package manifest
    pub fn build(mut self) -> PackageResult<EvidencePackageManifest> {
        // Collect artifacts based on scope
        self.collect_artifacts()?;
        
        // Compute chain heads
        let chain_heads = self.compute_chain_heads()?;
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let package_id = format!("pkg_{}_{}", self.tenant_id, now);
        
        Ok(EvidencePackageManifest {
            package_id,
            format_version: PACKAGE_FORMAT_VERSION,
            created_at: now,
            created_by: self.created_by,
            tenant_id: self.tenant_id,
            scope: self.scope,
            chain_heads,
            artifacts: self.artifacts,
            security: PackageSecurity {
                hash_algorithm: "sha256".to_string(),
                package_hash: String::new(),
                signature: None,
            },
            metadata: self.metadata,
        })
    }
    
    fn collect_artifacts(&mut self) -> PackageResult<()> {
        let scope = self.scope.clone();
        match scope {
            PackageScope::PolicyCommit { commit_id, framework } => {
                self.collect_by_policy_commit(&commit_id, framework.as_deref())?;
            }
            PackageScope::ComplianceBurn { burn_id, framework } => {
                self.collect_by_burn(&burn_id, &framework)?;
            }
            PackageScope::TimeRange { time_start, time_end, framework } => {
                self.collect_by_time_range(time_start, time_end, framework.as_deref())?;
            }
            PackageScope::Incident { incident_id: _, time_start, time_end } => {
                self.collect_by_time_range(time_start, time_end, None)?;
            }
            PackageScope::Custom { filters, .. } => {
                self.collect_by_custom_filters(&filters)?;
            }
        }
        
        Ok(())
    }
    
    fn collect_by_policy_commit(&mut self, commit_id: &str, framework: Option<&str>) -> PackageResult<()> {
        let db_path = self.dig_index_db.as_ref()
            .ok_or_else(|| PackageError::InvalidScope("dig_index_db not set".to_string()))?;
        
        let mut query = DigIndexQuery::new()
            .tenant(self.tenant_id.clone())
            .svc_commit(commit_id.to_string());
        
        if let Some(fw) = framework {
            query = query.compliance(fw.to_string());
        }
        
        let entries = query.execute(db_path)
            .map_err(|e| PackageError::IoError(format!("dig_index query failed: {}", e)))?;
        
        for entry in entries {
            self.add_digfile_artifact(&entry)?;
        }
        
        Ok(())
    }
    
    fn collect_by_burn(&mut self, burn_id: &str, _framework: &str) -> PackageResult<()> {
        let burn_root = self.burn_storage_root.as_ref()
            .ok_or_else(|| PackageError::InvalidScope("burn_storage_root not set".to_string()))?;
        
        let burn_path = PathBuf::from(burn_root).join(format!("{}.json", burn_id));
        
        if !burn_path.exists() {
            return Err(PackageError::MissingArtifact(format!("burn file not found: {:?}", burn_path)));
        }
        
        let content = std::fs::read_to_string(&burn_path)
            .map_err(|e| PackageError::IoError(format!("failed to read burn: {}", e)))?;
        
        let burn: ComplianceBurn = serde_json::from_str(&content)
            .map_err(|e| PackageError::SerializationError(format!("failed to parse burn: {}", e)))?;
        
        self.add_burn_artifact(&burn, burn_path.to_string_lossy().to_string())?;
        
        // Also collect DigFiles referenced by this burn if we have dig_index
        if let Some(ref db_path) = self.dig_index_db {
            if let Ok(entries) = DigIndexQuery::new()
                .tenant(self.tenant_id.clone())
                .burn(burn_id.to_string())
                .execute(db_path)
            {
                for entry in entries {
                    self.add_digfile_artifact(&entry)?;
                }
            }
        }
        
        Ok(())
    }
    
    fn collect_by_time_range(&mut self, start: u64, end: u64, framework: Option<&str>) -> PackageResult<()> {
        let db_path = self.dig_index_db.as_ref()
            .ok_or_else(|| PackageError::InvalidScope("dig_index_db not set".to_string()))?;
        
        let mut query = DigIndexQuery::new()
            .tenant(self.tenant_id.clone())
            .time_range(start, end);
        
        if let Some(fw) = framework {
            query = query.compliance(fw.to_string());
        }
        
        let entries = query.execute(db_path)
            .map_err(|e| PackageError::IoError(format!("dig_index query failed: {}", e)))?;
        
        for entry in entries {
            self.add_digfile_artifact(&entry)?;
        }
        
        Ok(())
    }
    
    fn collect_by_custom_filters(&mut self, filters: &HashMap<String, String>) -> PackageResult<()> {
        let db_path = self.dig_index_db.as_ref()
            .ok_or_else(|| PackageError::InvalidScope("dig_index_db not set".to_string()))?;
        
        let mut query = DigIndexQuery::new().tenant(self.tenant_id.clone());
        
        if let Some(svc) = filters.get("svc_commit") {
            query = query.svc_commit(svc.clone());
        }
        if let Some(frame) = filters.get("camera_frame") {
            query = query.camera_frame(frame.clone());
        }
        if let Some(actor) = filters.get("actor_did") {
            query = query.actor(actor.clone());
        }
        
        let entries = query.execute(db_path)
            .map_err(|e| PackageError::IoError(format!("dig_index query failed: {}", e)))?;
        
        for entry in entries {
            self.add_digfile_artifact(&entry)?;
        }
        
        Ok(())
    }
    
    fn add_digfile_artifact(&mut self, entry: &DigIndexEntry) -> PackageResult<()> {
        let storage_root = self.dig_storage_root.as_ref()
            .ok_or_else(|| PackageError::InvalidScope("dig_storage_root not set".to_string()))?;
        
        let path = if let Some(ref p) = entry.storage_path {
            PathBuf::from(p)
        } else {
            PathBuf::from(storage_root)
                .join(&entry.root_id)
                .join(format!("{}.json", entry.file_id))
        };
        
        if !path.exists() {
            return Err(PackageError::MissingArtifact(format!("DigFile not found: {:?}", path)));
        }
        
        let content = std::fs::read(&path)
            .map_err(|e| PackageError::IoError(format!("failed to read DigFile: {}", e)))?;
        
        let hash = compute_file_hash(&content);
        let size_bytes = content.len() as u64;
        
        // Parse to get metadata
        let dig: DigFile = serde_json::from_slice(&content)
            .map_err(|e| PackageError::SerializationError(format!("failed to parse DigFile: {}", e)))?;
        
        let metadata = ArtifactMetadata {
            merkle_root: Some(hex::encode(dig.merkle_root.0)),
            record_count: Some(dig.dig_records.len()),
            svc_commits: Some(entry.svc_commits.clone()),
            infra_version_id: entry.infra_version_id.clone(),
            camera_frames: Some(entry.camera_frames.clone()),
            actor_dids: Some(entry.actor_dids.clone()),
            time_start: Some(entry.time_start),
            time_end: Some(entry.time_end),
            ..Default::default()
        };
        
        self.artifacts.push(PackageArtifact {
            artifact_type: ArtifactType::DigFile,
            artifact_id: entry.file_id.clone(),
            path: Some(path.to_string_lossy().to_string()),
            hash,
            size_bytes: Some(size_bytes),
            metadata,
        });
        
        Ok(())
    }
    
    fn add_burn_artifact(&mut self, burn: &ComplianceBurn, path: String) -> PackageResult<()> {
        let content = std::fs::read(&path)
            .map_err(|e| PackageError::IoError(format!("failed to read burn: {}", e)))?;
        
        let hash = compute_file_hash(&content);
        let size_bytes = content.len() as u64;
        
        let metadata = ArtifactMetadata {
            burn_hash: Some(burn.burn_hash.clone()),
            prev_burn_hash: burn.prev_burn_hash.clone(),
            framework: Some(burn.summary.frameworks.join(",")),
            pass_rate: Some(burn.summary.pass_rate),
            time_start: Some(burn.summary.start_time),
            time_end: Some(burn.summary.end_time),
            ..Default::default()
        };
        
        self.artifacts.push(PackageArtifact {
            artifact_type: ArtifactType::ComplianceBurn,
            artifact_id: burn.burn_id.clone(),
            path: Some(path),
            hash,
            size_bytes: Some(size_bytes),
            metadata,
        });
        
        Ok(())
    }
    
    fn compute_chain_heads(&self) -> PackageResult<PackageChainHeads> {
        // Dig index head is optional when using SQLite (UTLD_DIG_INDEX_DB)
        // Only required when using JSONL chain mode (UTLD_DIG_INDEX)
        let dig_index_head = if std::env::var("UTLD_DIG_INDEX").is_ok() {
            read_chain_head("UTLD_DIG_INDEX", "./dig_index.jsonl")?
        } else {
            // Using SQLite mode - compute head from DB if available
            self.compute_dig_index_head_from_sqlite().unwrap_or_else(|_| "sqlite_mode".to_string())
        };
        
        let policy_ledger_head = read_chain_head_opt("UTLD_POLICY_LEDGER", "./policy_ledger.jsonl");
        let svc_ledger_head = read_chain_head_opt("UTLD_SVC_LEDGER", "./svc_ledger.jsonl");
        let burn_chain_head = read_chain_head_opt("UTLD_BURN_CHAIN", "./burn_chain.jsonl");
        let search_events_head = read_chain_head_opt("UTLD_SEARCH_EVENTS", "./search_events.jsonl");
        
        Ok(PackageChainHeads {
            dig_index_head,
            policy_ledger_head,
            svc_ledger_head,
            burn_chain_head,
            search_events_head,
        })
    }
    
    fn compute_dig_index_head_from_sqlite(&self) -> PackageResult<String> {
        let db_path = self.dig_index_db.as_ref()
            .ok_or_else(|| PackageError::IoError("dig_index_db not set".to_string()))?;
        
        // Query for the latest entry to compute a head hash
        let entries = DigIndexQuery::new()
            .tenant(self.tenant_id.clone())
            .limit(1)
            .execute(db_path)
            .map_err(|e| PackageError::IoError(format!("failed to query dig index: {}", e)))?;
        
        if let Some(entry) = entries.first() {
            // Compute a simple head hash from the latest entry
            let head_data = format!("{}:{}:{}", entry.file_id, entry.time_start, entry.time_end);
            let mut hasher = Sha256::new();
            hasher.update(head_data.as_bytes());
            Ok(hex::encode(hasher.finalize()))
        } else {
            Ok("empty".to_string())
        }
    }
}

fn compute_file_hash(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn read_chain_head(env_var: &str, default_path: &str) -> PackageResult<String> {
    let path = std::env::var(env_var).unwrap_or_else(|_| default_path.to_string());
    let head_path = format!("{}.head", path);
    
    std::fs::read_to_string(&head_path)
        .map(|s| s.trim().to_string())
        .map_err(|e| PackageError::IoError(format!("failed to read chain head {}: {}", head_path, e)))
}

fn read_chain_head_opt(env_var: &str, default_path: &str) -> Option<String> {
    read_chain_head(env_var, default_path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_constructs() {
        let scope = PackageScope::PolicyCommit {
            commit_id: "commit_123".to_string(),
            framework: Some("SOC2".to_string()),
        };
        
        let builder = PackageBuilder::new("tenant_a".to_string(), scope)
            .created_by("did:ritma:auditor:alice".to_string())
            .metadata("purpose".to_string(), "Q4 audit".to_string());
        
        assert_eq!(builder.tenant_id, "tenant_a");
    }
}
