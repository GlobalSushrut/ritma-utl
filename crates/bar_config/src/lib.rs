//! BAR Configuration Module
//!
//! Implements ConfigPower with layered configuration, schema validation, and diffing.
//!
//! # Architecture
//!
//! - **Layered Config**: Merge configs from multiple sources (defaults, files, env vars)
//! - **Schema Validation**: JSON Schema validation for config integrity
//! - **Config Diffing**: Track changes between config versions
//! - **Hash-based Versioning**: SHA-256 hashing for config identity

use common_models::NamespaceId;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
    
    #[error("Schema validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("Config not found: {0}")]
    NotFound(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("IO error: {0}")]
    IoError(String),
}

/// Configuration layer priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfigLayer {
    Default = 0,
    File = 1,
    Environment = 2,
    Runtime = 3,
}

/// Configuration source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSource {
    pub layer: String,
    pub source_path: Option<String>,
    pub loaded_at: String,
}

/// Layered configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayeredConfig {
    pub namespace_id: String,
    pub config_hash: String,
    pub layers: Vec<ConfigLayer>,
    pub merged_config: JsonValue,
    pub sources: Vec<ConfigSource>,
}

impl LayeredConfig {
    /// Compute SHA-256 hash of the merged configuration
    pub fn compute_hash(config: &JsonValue) -> String {
        use sha2::{Digest, Sha256};
        let serialized = serde_json::to_string(config).unwrap_or_default();
        let hash = Sha256::digest(serialized.as_bytes());
        hex::encode(hash)
    }
}

/// Configuration diff entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConfigDiffEntry {
    Added { path: String, value: JsonValue },
    Removed { path: String, value: JsonValue },
    Modified { path: String, old_value: JsonValue, new_value: JsonValue },
}

/// Configuration diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigDiff {
    pub from_hash: String,
    pub to_hash: String,
    pub changes: Vec<ConfigDiffEntry>,
}

impl ConfigDiff {
    /// Create a diff between two configurations
    pub fn diff(from: &JsonValue, to: &JsonValue) -> Self {
        let from_hash = LayeredConfig::compute_hash(from);
        let to_hash = LayeredConfig::compute_hash(to);
        let changes = Self::diff_values("", from, to);
        
        ConfigDiff {
            from_hash,
            to_hash,
            changes,
        }
    }
    
    fn diff_values(path: &str, from: &JsonValue, to: &JsonValue) -> Vec<ConfigDiffEntry> {
        let mut changes = Vec::new();
        
        match (from, to) {
            (JsonValue::Object(from_obj), JsonValue::Object(to_obj)) => {
                // Check for removed and modified keys
                for (key, from_val) in from_obj {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    
                    if let Some(to_val) = to_obj.get(key) {
                        if from_val != to_val {
                            // Recursively diff nested objects
                            if from_val.is_object() && to_val.is_object() {
                                changes.extend(Self::diff_values(&new_path, from_val, to_val));
                            } else {
                                changes.push(ConfigDiffEntry::Modified {
                                    path: new_path,
                                    old_value: from_val.clone(),
                                    new_value: to_val.clone(),
                                });
                            }
                        }
                    } else {
                        changes.push(ConfigDiffEntry::Removed {
                            path: new_path,
                            value: from_val.clone(),
                        });
                    }
                }
                
                // Check for added keys
                for (key, to_val) in to_obj {
                    if !from_obj.contains_key(key) {
                        let new_path = if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{}.{}", path, key)
                        };
                        changes.push(ConfigDiffEntry::Added {
                            path: new_path,
                            value: to_val.clone(),
                        });
                    }
                }
            }
            _ => {
                if from != to {
                    changes.push(ConfigDiffEntry::Modified {
                        path: path.to_string(),
                        old_value: from.clone(),
                        new_value: to.clone(),
                    });
                }
            }
        }
        
        changes
    }
    
    /// Check if diff has any changes
    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }
}

/// Configuration manager with layering and validation
pub struct ConfigManager {
    configs: HashMap<String, LayeredConfig>,
    schemas: HashMap<String, JsonValue>,
}

impl ConfigManager {
    pub fn new() -> Self {
        Self {
            configs: HashMap::new(),
            schemas: HashMap::new(),
        }
    }
    
    /// Register a JSON schema for a namespace
    pub fn register_schema(&mut self, namespace_id: String, schema: JsonValue) {
        self.schemas.insert(namespace_id, schema);
    }
    
    /// Validate config against registered schema
    pub fn validate(&self, namespace_id: &str, config: &JsonValue) -> Result<(), ConfigError> {
        if let Some(schema) = self.schemas.get(namespace_id) {
            let compiled = jsonschema::JSONSchema::compile(schema)
                .map_err(|e| ConfigError::ValidationFailed(format!("Schema compilation failed: {}", e)))?;
            
            let result = compiled.validate(config);
            if let Err(errors) = result {
                let error_msgs: Vec<String> = errors
                    .map(|e| format!("{}", e))
                    .collect();
                return Err(ConfigError::ValidationFailed(error_msgs.join(", ")));
            }
        }
        
        Ok(())
    }
    
    /// Load and merge layered configuration
    pub fn load_layered(
        &mut self,
        namespace_id: String,
        layers: Vec<(ConfigLayer, JsonValue, Option<String>)>,
    ) -> Result<LayeredConfig, ConfigError> {
        // Sort layers by priority
        let mut sorted_layers = layers;
        sorted_layers.sort_by_key(|(layer, _, _)| *layer);
        
        // Merge configurations
        let mut merged = JsonValue::Object(serde_json::Map::new());
        let mut sources = Vec::new();
        
        for (layer, config, source_path) in sorted_layers {
            Self::merge_json(&mut merged, &config);
            sources.push(ConfigSource {
                layer: format!("{:?}", layer),
                source_path,
                loaded_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        
        // Validate merged config
        self.validate(&namespace_id, &merged)?;
        
        let config_hash = LayeredConfig::compute_hash(&merged);
        
        let layered_config = LayeredConfig {
            namespace_id: namespace_id.clone(),
            config_hash,
            layers: vec![], // Simplified for now
            merged_config: merged,
            sources,
        };
        
        self.configs.insert(namespace_id, layered_config.clone());
        
        Ok(layered_config)
    }
    
    /// Merge two JSON values (right takes precedence)
    fn merge_json(left: &mut JsonValue, right: &JsonValue) {
        match (left, right) {
            (JsonValue::Object(left_obj), JsonValue::Object(right_obj)) => {
                for (key, right_val) in right_obj {
                    if let Some(left_val) = left_obj.get_mut(key) {
                        Self::merge_json(left_val, right_val);
                    } else {
                        left_obj.insert(key.clone(), right_val.clone());
                    }
                }
            }
            (left_val, right_val) => {
                *left_val = right_val.clone();
            }
        }
    }
    
    /// Get configuration for a namespace
    pub fn get(&self, namespace_id: &str) -> Option<&LayeredConfig> {
        self.configs.get(namespace_id)
    }
    
    /// Update configuration and return diff
    pub fn update(
        &mut self,
        namespace_id: String,
        new_config: JsonValue,
    ) -> Result<ConfigDiff, ConfigError> {
        // Validate new config
        self.validate(&namespace_id, &new_config)?;
        
        // Get old config for diff
        let old_config = self.configs.get(&namespace_id)
            .map(|c| c.merged_config.clone())
            .unwrap_or_else(|| JsonValue::Object(serde_json::Map::new()));
        
        // Compute diff
        let diff = ConfigDiff::diff(&old_config, &new_config);
        
        // Update config
        let config_hash = LayeredConfig::compute_hash(&new_config);
        let layered_config = LayeredConfig {
            namespace_id: namespace_id.clone(),
            config_hash,
            layers: vec![],
            merged_config: new_config,
            sources: vec![ConfigSource {
                layer: "Runtime".to_string(),
                source_path: None,
                loaded_at: chrono::Utc::now().to_rfc3339(),
            }],
        };
        
        self.configs.insert(namespace_id, layered_config);
        
        Ok(diff)
    }
    
    /// Remove configuration
    pub fn remove(&mut self, namespace_id: &str) -> Option<LayeredConfig> {
        self.configs.remove(namespace_id)
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn config_hash_is_deterministic() {
        let config1 = serde_json::json!({"key": "value", "num": 42});
        let config2 = serde_json::json!({"key": "value", "num": 42});
        
        let hash1 = LayeredConfig::compute_hash(&config1);
        let hash2 = LayeredConfig::compute_hash(&config2);
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex
    }
    
    #[test]
    fn config_diff_detects_changes() {
        let from = serde_json::json!({
            "key1": "value1",
            "key2": 42,
            "nested": {
                "inner": "old"
            }
        });
        
        let to = serde_json::json!({
            "key1": "value1",
            "key2": 43,
            "key3": "new",
            "nested": {
                "inner": "new"
            }
        });
        
        let diff = ConfigDiff::diff(&from, &to);
        
        assert!(diff.has_changes());
        assert_eq!(diff.changes.len(), 3); // Modified key2, added key3, modified nested.inner
    }
    
    #[test]
    fn config_manager_validates_schema() {
        let mut manager = ConfigManager::new();
        
        // Register schema
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "number"}
            },
            "required": ["name"]
        });
        
        manager.register_schema("ns://test/prod/app/svc".to_string(), schema);
        
        // Valid config
        let valid_config = serde_json::json!({"name": "test", "age": 30});
        assert!(manager.validate("ns://test/prod/app/svc", &valid_config).is_ok());
        
        // Invalid config (missing required field)
        let invalid_config = serde_json::json!({"age": 30});
        assert!(manager.validate("ns://test/prod/app/svc", &invalid_config).is_err());
    }
    
    #[test]
    fn config_manager_merges_layers() {
        let mut manager = ConfigManager::new();
        
        let default_config = serde_json::json!({
            "timeout": 30,
            "retries": 3,
            "endpoint": "http://default"
        });
        
        let file_config = serde_json::json!({
            "endpoint": "http://prod",
            "debug": false
        });
        
        let env_config = serde_json::json!({
            "timeout": 60
        });
        
        let layers = vec![
            (ConfigLayer::Default, default_config, Some("defaults.json".to_string())),
            (ConfigLayer::File, file_config, Some("config.json".to_string())),
            (ConfigLayer::Environment, env_config, None),
        ];
        
        let result = manager.load_layered("ns://test/prod/app/svc".to_string(), layers)
            .expect("load layered");
        
        // Check merged values (later layers override earlier ones)
        let merged = &result.merged_config;
        assert_eq!(merged["timeout"], 60); // From env
        assert_eq!(merged["retries"], 3); // From default
        assert_eq!(merged["endpoint"], "http://prod"); // From file
        assert_eq!(merged["debug"], false); // From file
    }
    
    #[test]
    fn config_manager_tracks_updates() {
        let mut manager = ConfigManager::new();
        
        let initial = serde_json::json!({"version": 1, "enabled": true});
        let updated = serde_json::json!({"version": 2, "enabled": false, "new_field": "test"});
        
        // Load initial
        manager.load_layered(
            "ns://test/prod/app/svc".to_string(),
            vec![(ConfigLayer::Default, initial, None)],
        ).expect("load");
        
        // Update and get diff
        let diff = manager.update("ns://test/prod/app/svc".to_string(), updated)
            .expect("update");
        
        assert!(diff.has_changes());
        assert_eq!(diff.changes.len(), 3); // version modified, enabled modified, new_field added
    }
}
