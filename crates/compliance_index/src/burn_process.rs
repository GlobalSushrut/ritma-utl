// Compliance Burn Process Orchestrator
// Manages the end-to-end process of creating, storing, and verifying compliance burns

use crate::{BurnBuilder, ComplianceBurn, ControlEvalRecord};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// Burn process configuration
#[derive(Debug, Clone)]
pub struct BurnConfig {
    /// Directory to store burn files
    pub burn_dir: String,

    /// Automatically sign burns
    pub auto_sign: bool,

    /// Signing key ID (for signature)
    pub signing_key_id: Option<String>,
}

impl Default for BurnConfig {
    fn default() -> Self {
        Self {
            burn_dir: "./compliance_burns".to_string(),
            auto_sign: false,
            signing_key_id: None,
        }
    }
}

/// Burn process orchestrator
pub struct BurnProcess {
    config: BurnConfig,
}

impl BurnProcess {
    pub fn new(config: BurnConfig) -> Self {
        Self { config }
    }

    /// Create a new compliance burn from records
    pub fn create_burn(
        &self,
        tenant_id: &str,
        framework: &str,
        records: Vec<ControlEvalRecord>,
    ) -> Result<ComplianceBurn, String> {
        // Get previous burn hash for chaining
        let prev_burn_hash = self.get_last_burn_hash(tenant_id, framework)?;

        // Build burn
        let mut builder =
            BurnBuilder::new(tenant_id.to_string(), framework.to_string()).add_records(records);

        if let Some(prev_hash) = prev_burn_hash {
            builder = builder.with_prev_burn(prev_hash);
        }

        let mut burn = builder.build()?;

        // Sign if configured
        if self.config.auto_sign {
            burn.signature = Some(self.sign_burn(&burn)?);
        }

        Ok(burn)
    }

    /// Persist a burn to disk
    pub fn persist_burn(&self, burn: &ComplianceBurn) -> Result<String, String> {
        // Ensure burn directory exists
        std::fs::create_dir_all(&self.config.burn_dir)
            .map_err(|e| format!("Failed to create burn directory: {e}"))?;

        // Create burn file path
        let filename = format!("{}.burn.json", burn.burn_id);
        let filepath = Path::new(&self.config.burn_dir).join(&filename);

        // Write burn to file
        let json = serde_json::to_string_pretty(burn)
            .map_err(|e| format!("Failed to serialize burn: {e}"))?;

        std::fs::write(&filepath, json).map_err(|e| format!("Failed to write burn file: {e}"))?;

        // Append to burn chain index
        self.append_to_chain_index(burn)?;

        Ok(filepath.to_string_lossy().to_string())
    }

    /// Load a burn from disk
    pub fn load_burn(&self, burn_id: &str) -> Result<ComplianceBurn, String> {
        let filename = format!("{burn_id}.burn.json");
        let filepath = Path::new(&self.config.burn_dir).join(&filename);

        let json = std::fs::read_to_string(&filepath)
            .map_err(|e| format!("Failed to read burn file: {e}"))?;

        serde_json::from_str(&json).map_err(|e| format!("Failed to parse burn: {e}"))
    }

    /// Get all burns for a tenant/framework
    pub fn get_burns(
        &self,
        tenant_id: &str,
        framework: &str,
    ) -> Result<Vec<ComplianceBurn>, String> {
        let index_path = self.get_chain_index_path(tenant_id, framework);

        if !Path::new(&index_path).exists() {
            return Ok(Vec::new());
        }

        let file =
            File::open(&index_path).map_err(|e| format!("Failed to open chain index: {e}"))?;

        let reader = BufReader::new(file);
        let mut burns = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Failed to read line: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }

            let burn_id: String =
                serde_json::from_str(&line).map_err(|e| format!("Failed to parse burn ID: {e}"))?;

            let burn = self.load_burn(&burn_id)?;
            burns.push(burn);
        }

        Ok(burns)
    }

    /// Verify integrity of all burns in a chain
    pub fn verify_chain(&self, tenant_id: &str, framework: &str) -> Result<(), String> {
        let burns = self.get_burns(tenant_id, framework)?;
        crate::burn::verify_burn_chain(&burns)
    }

    /// Execute a burn process: collect records, create burn, persist
    pub fn execute_burn(
        &self,
        tenant_id: &str,
        framework: &str,
        records: Vec<ControlEvalRecord>,
    ) -> Result<ComplianceBurn, String> {
        // Create burn
        let burn = self.create_burn(tenant_id, framework, records)?;

        // Persist to disk
        let filepath = self.persist_burn(&burn)?;

        println!("✅ Compliance burn created: {}", burn.burn_id);
        println!("   Merkle root: {}", burn.merkle_root);
        println!("   Records: {}", burn.record_count);
        println!("   Pass rate: {:.1}%", burn.summary.pass_rate);
        println!("   File: {filepath}");

        Ok(burn)
    }

    /// Get the last burn hash for chaining
    fn get_last_burn_hash(
        &self,
        tenant_id: &str,
        framework: &str,
    ) -> Result<Option<String>, String> {
        let burns = self.get_burns(tenant_id, framework)?;
        Ok(burns.last().map(|b| b.burn_hash.clone()))
    }

    /// Append burn ID to chain index
    fn append_to_chain_index(&self, burn: &ComplianceBurn) -> Result<(), String> {
        let index_path = self.get_chain_index_path(&burn.tenant_id, &burn.framework);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index_path)
            .map_err(|e| format!("Failed to open chain index: {e}"))?;

        let line = format!("{}\n", serde_json::to_string(&burn.burn_id).unwrap());
        file.write_all(line.as_bytes())
            .map_err(|e| format!("Failed to write to chain index: {e}"))?;

        Ok(())
    }

    /// Get path to chain index file
    fn get_chain_index_path(&self, tenant_id: &str, framework: &str) -> String {
        Path::new(&self.config.burn_dir)
            .join(format!("{tenant_id}_{framework}_chain.index"))
            .to_string_lossy()
            .to_string()
    }

    /// Sign a burn using the node keystore.
    fn sign_burn(&self, burn: &ComplianceBurn) -> Result<String, String> {
        let key_id = match &self.config.signing_key_id {
            Some(id) => id.clone(),
            None => return Err("signing_key_id is not configured for burn signing".to_string()),
        };

        let ks = node_keystore::NodeKeystore::from_env()
            .map_err(|e| format!("failed to load node keystore: {e}"))?;

        let sig_hex = ks
            .sign_bytes(&key_id, burn.burn_hash.as_bytes())
            .map_err(|e| format!("failed to sign burn with key {key_id}: {e}"))?;

        Ok(format!("sig_{sig_hex}"))
    }
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
    fn burn_process_creates_and_persists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = BurnConfig {
            burn_dir: temp_dir.path().to_string_lossy().to_string(),
            auto_sign: false,
            signing_key_id: None,
        };

        let process = BurnProcess::new(config);

        let records = vec![
            create_test_record("AC-1", true),
            create_test_record("AC-2", false),
        ];

        let burn = process.execute_burn("tenant_a", "SOC2", records).unwrap();

        assert!(burn.signature.is_none());
        assert_eq!(burn.record_count, 2);

        // Verify we can load it back
        let loaded = process.load_burn(&burn.burn_id).unwrap();
        assert_eq!(loaded.burn_hash, burn.burn_hash);
    }

    #[test]
    fn burn_chain_maintains_integrity() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = BurnConfig {
            burn_dir: temp_dir.path().to_string_lossy().to_string(),
            auto_sign: false,
            signing_key_id: None,
        };

        let process = BurnProcess::new(config);

        // Create first burn
        let burn1 = process
            .execute_burn("tenant_a", "SOC2", vec![create_test_record("AC-1", true)])
            .unwrap();

        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Create second burn (should chain to first)
        let burn2 = process
            .execute_burn("tenant_a", "SOC2", vec![create_test_record("AC-2", true)])
            .unwrap();

        assert_eq!(burn2.prev_burn_hash, Some(burn1.burn_hash.clone()));

        // Verify chain integrity
        let result = process.verify_chain("tenant_a", "SOC2");
        if let Err(e) = &result {
            eprintln!("Chain verification failed: {}", e);
        }
        assert!(result.is_ok());
    }
}
