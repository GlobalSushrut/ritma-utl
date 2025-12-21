use common_models::NamespaceId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NamespaceError {
    #[error("namespace not found: {0}")]
    NotFound(String),
    #[error("invalid namespace: {0}")]
    Invalid(String),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NamespaceError>;

/// Namespace configuration and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceConfig {
    pub namespace_id: String,
    pub org: String,
    pub env: String,
    pub app: String,
    pub service: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Namespace registry for managing namespace configurations
pub struct NamespaceRegistry {
    namespaces: HashMap<String, NamespaceConfig>,
}

impl NamespaceRegistry {
    pub fn new() -> Self {
        Self {
            namespaces: HashMap::new(),
        }
    }

    pub fn register(&mut self, config: NamespaceConfig) -> Result<()> {
        let ns_id = NamespaceId::parse(&config.namespace_id)
            .map_err(|e| NamespaceError::Invalid(e.to_string()))?;
        
        self.namespaces.insert(ns_id.as_str().to_string(), config);
        Ok(())
    }

    pub fn get(&self, namespace_id: &str) -> Result<&NamespaceConfig> {
        self.namespaces
            .get(namespace_id)
            .ok_or_else(|| NamespaceError::NotFound(namespace_id.to_string()))
    }

    pub fn list(&self) -> Vec<&NamespaceConfig> {
        self.namespaces.values().collect()
    }

    pub fn remove(&mut self, namespace_id: &str) -> Result<()> {
        self.namespaces
            .remove(namespace_id)
            .ok_or_else(|| NamespaceError::NotFound(namespace_id.to_string()))?;
        Ok(())
    }
}

impl Default for NamespaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_registry_basic_operations() {
        let mut registry = NamespaceRegistry::new();

        let config = NamespaceConfig {
            namespace_id: "ns://acme/prod/payments/api".to_string(),
            org: "acme".to_string(),
            env: "prod".to_string(),
            app: "payments".to_string(),
            service: "api".to_string(),
            metadata: HashMap::new(),
        };

        registry.register(config.clone()).expect("register");
        
        let retrieved = registry.get("ns://acme/prod/payments/api").expect("get");
        assert_eq!(retrieved.org, "acme");
        assert_eq!(retrieved.env, "prod");

        let list = registry.list();
        assert_eq!(list.len(), 1);

        registry.remove("ns://acme/prod/payments/api").expect("remove");
        assert!(registry.get("ns://acme/prod/payments/api").is_err());
    }

    #[test]
    fn namespace_registry_rejects_invalid() {
        let mut registry = NamespaceRegistry::new();

        let config = NamespaceConfig {
            namespace_id: "invalid".to_string(),
            org: "acme".to_string(),
            env: "prod".to_string(),
            app: "payments".to_string(),
            service: "api".to_string(),
            metadata: HashMap::new(),
        };

        assert!(registry.register(config).is_err());
    }
}
