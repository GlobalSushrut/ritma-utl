use common_models::{NamespaceId, hash_string_sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("invalid contract: {0}")]
    Invalid(String),
    #[error("contract not found: {0}")]
    NotFound(String),
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ContractError>;

/// Agent Contract that bounds BAR's powers and ranges per namespace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContract {
    pub contract_id: String,
    pub version: String,
    pub namespaces: Vec<String>,
    pub pack_allowlist: Vec<String>,
    pub data_boundaries: DataBoundaries,
    pub action_boundaries: ActionBoundaries,
    pub routes: Vec<Route>,
    pub validity_ranges: ValidityRanges,
    pub failure_policy: FailurePolicy,
    pub signing: ContractSigning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBoundaries {
    pub allowed_fields: Vec<String>,
    pub redaction_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionBoundaries {
    pub allowed_actions: Vec<String>,
    pub denied_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub match_pattern: String,
    pub destinations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityRanges {
    #[serde(default)]
    pub time: Option<TimeRange>,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub jurisdiction: Option<Vec<String>>,
    #[serde(default)]
    pub service_versions: Option<Vec<String>>,
    #[serde(default)]
    pub policy_versions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    FailOpen,
    FailClosed,
    Degrade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSigning {
    pub pubkey_id: String,
    pub signature: String,
    pub algorithm: String,
}

impl AgentContract {
    /// Compute the canonical hash of this contract
    pub fn compute_hash(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        hash_string_sha256(&json)
    }

    /// Check if this contract is valid for a given namespace
    pub fn is_valid_for_namespace(&self, namespace_id: &str) -> bool {
        self.namespaces.iter().any(|ns| ns == namespace_id)
    }

    /// Check if a pack is allowed by this contract
    pub fn is_pack_allowed(&self, pack_name: &str) -> bool {
        self.pack_allowlist.iter().any(|p| p == pack_name)
    }
}

/// Contract registry for managing active contracts
pub struct ContractRegistry {
    contracts: HashMap<String, AgentContract>,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self {
            contracts: HashMap::new(),
        }
    }

    pub fn register(&mut self, contract: AgentContract) -> Result<String> {
        let hash = contract.compute_hash();
        self.contracts.insert(hash.clone(), contract);
        Ok(hash)
    }

    pub fn get(&self, contract_hash: &str) -> Result<&AgentContract> {
        self.contracts
            .get(contract_hash)
            .ok_or_else(|| ContractError::NotFound(contract_hash.to_string()))
    }

    pub fn list(&self) -> Vec<&AgentContract> {
        self.contracts.values().collect()
    }

    pub fn find_for_namespace(&self, namespace_id: &str) -> Vec<&AgentContract> {
        self.contracts
            .values()
            .filter(|c| c.is_valid_for_namespace(namespace_id))
            .collect()
    }

    pub fn remove(&mut self, contract_hash: &str) -> Result<()> {
        self.contracts
            .remove(contract_hash)
            .ok_or_else(|| ContractError::NotFound(contract_hash.to_string()))?;
        Ok(())
    }
}

impl Default for ContractRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_contract() -> AgentContract {
        AgentContract {
            contract_id: "contract_1".to_string(),
            version: "1.0.0".to_string(),
            namespaces: vec!["ns://acme/prod/payments/api".to_string()],
            pack_allowlist: vec!["baseline".to_string(), "access_control".to_string()],
            data_boundaries: DataBoundaries {
                allowed_fields: vec!["user_id".to_string()],
                redaction_rules: vec!["pii".to_string()],
            },
            action_boundaries: ActionBoundaries {
                allowed_actions: vec!["read".to_string(), "write".to_string()],
                denied_actions: vec!["delete".to_string()],
            },
            routes: vec![Route {
                match_pattern: "AUTH.*".to_string(),
                destinations: vec!["utl".to_string(), "index_db".to_string()],
            }],
            validity_ranges: ValidityRanges {
                time: Some(TimeRange {
                    not_before: "2025-01-01T00:00:00Z".to_string(),
                    not_after: "2026-01-01T00:00:00Z".to_string(),
                }),
                env: Some(vec!["prod".to_string()]),
                jurisdiction: None,
                service_versions: None,
                policy_versions: None,
            },
            failure_policy: FailurePolicy::FailOpen,
            signing: ContractSigning {
                pubkey_id: "key_1".to_string(),
                signature: "sig_placeholder".to_string(),
                algorithm: "ed25519".to_string(),
            },
        }
    }

    #[test]
    fn contract_computes_hash() {
        let contract = create_test_contract();
        let hash = contract.compute_hash();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 hex
    }

    #[test]
    fn contract_validates_namespace() {
        let contract = create_test_contract();
        assert!(contract.is_valid_for_namespace("ns://acme/prod/payments/api"));
        assert!(!contract.is_valid_for_namespace("ns://other/prod/app/svc"));
    }

    #[test]
    fn contract_validates_pack() {
        let contract = create_test_contract();
        assert!(contract.is_pack_allowed("baseline"));
        assert!(!contract.is_pack_allowed("unknown"));
    }

    #[test]
    fn registry_basic_operations() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        
        let hash = registry.register(contract.clone()).expect("register");
        
        let retrieved = registry.get(&hash).expect("get");
        assert_eq!(retrieved.contract_id, "contract_1");
        
        let for_ns = registry.find_for_namespace("ns://acme/prod/payments/api");
        assert_eq!(for_ns.len(), 1);
        
        registry.remove(&hash).expect("remove");
        assert!(registry.get(&hash).is_err());
    }
}
