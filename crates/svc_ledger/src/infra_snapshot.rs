// Infrastructure Snapshot - Version Tree for Security Infrastructure
// Captures complete state of security infra at a point in time

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Infrastructure snapshot capturing full security state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfraSnapshot {
    /// Unique snapshot ID
    pub snapshot_id: String,

    /// Timestamp
    pub timestamp: u64,

    /// Tenant ID
    pub tenant_id: Option<String>,

    /// Parent snapshot ID (for versioning)
    pub parent_id: Option<String>,

    /// Infrastructure layers
    pub layers: HashMap<String, InfraLayer>,

    /// Merkle root over all layer hashes
    pub merkle_root: String,

    /// Hash of this snapshot
    pub snapshot_hash: String,
}

/// A single infrastructure layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfraLayer {
    /// Layer name (kernel, ebpf, network, cgroup, service, policy, consensus)
    pub name: String,

    /// Layer hash
    pub hash: String,

    /// Layer metadata
    pub metadata: HashMap<String, String>,

    /// Components in this layer
    pub components: Vec<InfraComponent>,
}

/// A component within an infrastructure layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfraComponent {
    /// Component name
    pub name: String,

    /// Component type
    pub component_type: String,

    /// Version/hash
    pub version: String,

    /// Configuration hash
    pub config_hash: Option<String>,

    /// Status
    pub status: String,
}

/// Infrastructure version ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InfraVersionId {
    pub tenant_id: Option<String>,
    pub hash: String,
}

impl InfraVersionId {
    pub fn new(tenant_id: Option<String>, hash: String) -> Self {
        Self { tenant_id, hash }
    }

    /// Format as infra:// URI
    pub fn to_uri(&self) -> String {
        if let Some(ref tenant) = self.tenant_id {
            format!("infra://{}/{}", tenant, self.hash)
        } else {
            format!("infra://global/{}", self.hash)
        }
    }
}

/// Builder for infrastructure snapshots
pub struct InfraSnapshotBuilder {
    tenant_id: Option<String>,
    parent_id: Option<String>,
    layers: HashMap<String, InfraLayer>,
}

impl InfraSnapshotBuilder {
    pub fn new(tenant_id: Option<String>) -> Self {
        Self {
            tenant_id,
            parent_id: None,
            layers: HashMap::new(),
        }
    }

    pub fn with_parent(mut self, parent_id: String) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    pub fn add_layer(mut self, layer: InfraLayer) -> Self {
        self.layers.insert(layer.name.clone(), layer);
        self
    }

    /// Build the snapshot
    pub fn build(self) -> Result<InfraSnapshot, String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute Merkle root over layer hashes
        let layer_hashes: Vec<String> = self.layers.values().map(|l| l.hash.clone()).collect();
        let merkle_root = compute_merkle_root(&layer_hashes)?;

        // Generate snapshot ID
        let snapshot_id = format!(
            "infra_{}_{}",
            self.tenant_id.as_deref().unwrap_or("global"),
            timestamp
        );

        let mut snapshot = InfraSnapshot {
            snapshot_id,
            timestamp,
            tenant_id: self.tenant_id,
            parent_id: self.parent_id,
            layers: self.layers,
            merkle_root,
            snapshot_hash: String::new(),
        };

        // Compute snapshot hash
        snapshot.snapshot_hash = compute_snapshot_hash(&snapshot)?;

        Ok(snapshot)
    }
}

/// Compute Merkle root from layer hashes
fn compute_merkle_root(hashes: &[String]) -> Result<String, String> {
    if hashes.is_empty() {
        return Err("Cannot compute Merkle root with no hashes".to_string());
    }

    let mut current_level: Vec<String> = hashes.to_vec();

    while current_level.len() > 1 {
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
    }

    Ok(current_level[0].clone())
}

/// Compute hash of snapshot
fn compute_snapshot_hash(snapshot: &InfraSnapshot) -> Result<String, String> {
    let mut hashable = snapshot.clone();
    hashable.snapshot_hash = String::new();

    let json = serde_json::to_string(&hashable).map_err(|e| format!("Failed to serialize: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Helper to create common infrastructure layers
pub mod layers {
    use super::*;

    pub fn kernel_layer(version: &str, sysctls: Vec<(&str, &str)>) -> InfraLayer {
        let mut metadata = HashMap::new();
        metadata.insert("kernel_version".to_string(), version.to_string());

        for (key, val) in sysctls {
            metadata.insert(key.to_string(), val.to_string());
        }

        let hash = compute_layer_hash("kernel", &metadata);

        InfraLayer {
            name: "kernel".to_string(),
            hash,
            metadata,
            components: vec![],
        }
    }

    pub fn ebpf_layer(programs: Vec<(&str, &str)>) -> InfraLayer {
        let components: Vec<InfraComponent> = programs
            .iter()
            .map(|(name, hash)| InfraComponent {
                name: name.to_string(),
                component_type: "xdp_program".to_string(),
                version: hash.to_string(),
                config_hash: None,
                status: "loaded".to_string(),
            })
            .collect();

        let mut metadata = HashMap::new();
        metadata.insert("program_count".to_string(), components.len().to_string());

        let hash = compute_layer_hash("ebpf", &metadata);

        InfraLayer {
            name: "ebpf".to_string(),
            hash,
            metadata,
            components,
        }
    }

    pub fn cgroup_layer(profiles: Vec<(&str, u32, u64)>) -> InfraLayer {
        let components: Vec<InfraComponent> = profiles
            .iter()
            .map(|(name, cpu, mem)| InfraComponent {
                name: name.to_string(),
                component_type: "cgroup_profile".to_string(),
                version: format!("cpu:{cpu}_mem:{mem}"),
                config_hash: None,
                status: "active".to_string(),
            })
            .collect();

        let mut metadata = HashMap::new();
        metadata.insert("profile_count".to_string(), components.len().to_string());

        let hash = compute_layer_hash("cgroup", &metadata);

        InfraLayer {
            name: "cgroup".to_string(),
            hash,
            metadata,
            components,
        }
    }

    pub fn policy_layer(policies: Vec<(&str, &str)>) -> InfraLayer {
        let components: Vec<InfraComponent> = policies
            .iter()
            .map(|(name, hash)| InfraComponent {
                name: name.to_string(),
                component_type: "truthscript_v2".to_string(),
                version: hash.to_string(),
                config_hash: Some(hash.to_string()),
                status: "active".to_string(),
            })
            .collect();

        let mut metadata = HashMap::new();
        metadata.insert("policy_count".to_string(), components.len().to_string());

        let hash = compute_layer_hash("policy", &metadata);

        InfraLayer {
            name: "policy".to_string(),
            hash,
            metadata,
            components,
        }
    }

    fn compute_layer_hash(name: &str, metadata: &HashMap<String, String>) -> String {
        let json = serde_json::to_string(&(name, metadata)).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infra_snapshot_builds() {
        let kernel = layers::kernel_layer("5.15.0", vec![("net.ipv4.ip_forward", "1")]);

        let ebpf = layers::ebpf_layer(vec![("ritma_xdp", "abc123")]);

        let snapshot = InfraSnapshotBuilder::new(Some("tenant_a".to_string()))
            .add_layer(kernel)
            .add_layer(ebpf)
            .build()
            .unwrap();

        assert!(!snapshot.snapshot_hash.is_empty());
        assert!(!snapshot.merkle_root.is_empty());
        assert_eq!(snapshot.layers.len(), 2);
    }

    #[test]
    fn infra_version_id_formats_uri() {
        let id = InfraVersionId::new(Some("tenant_a".to_string()), "hash123".to_string());
        let uri = id.to_uri();
        assert_eq!(uri, "infra://tenant_a/hash123");
    }

    #[test]
    fn infra_snapshot_chains() {
        let snapshot1 = InfraSnapshotBuilder::new(Some("tenant_a".to_string()))
            .add_layer(layers::kernel_layer("5.15.0", vec![]))
            .build()
            .unwrap();

        let snapshot2 = InfraSnapshotBuilder::new(Some("tenant_a".to_string()))
            .with_parent(snapshot1.snapshot_hash.clone())
            .add_layer(layers::kernel_layer("5.16.0", vec![]))
            .build()
            .unwrap();

        assert_eq!(snapshot2.parent_id, Some(snapshot1.snapshot_hash));
    }
}
