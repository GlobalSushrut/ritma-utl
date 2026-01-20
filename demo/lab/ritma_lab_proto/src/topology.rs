use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Topology {
    pub version: String,
    pub metadata: TopologyMetadata,
    pub nodes: Vec<NodeSpec>,
    pub networks: Vec<NetworkSpec>,
    pub aggregator: AggregatorSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyMetadata {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_run_id")]
    pub run_id: String,
    #[serde(default)]
    pub seed: u64,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

fn default_run_id() -> String {
    format!("run_{}", uuid::Uuid::now_v7())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSpec {
    pub id: String,
    pub role: NodeRole,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub resources: ResourceSpec,
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    #[serde(default)]
    pub environment: HashMap<String, String>,
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
    #[serde(default)]
    pub ritma: RitmaAgentSpec,
    #[serde(default)]
    pub workload: WorkloadSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Frontend,
    Backend,
    Database,
    Cache,
    Queue,
    MlInference,
    FileServer,
    Workstation,
    Custom(String),
}

impl Default for NodeRole {
    fn default() -> Self {
        NodeRole::Custom("generic".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    #[serde(default = "default_memory")]
    pub memory: String,
    #[serde(default = "default_cpu")]
    pub cpu: String,
}

impl Default for ResourceSpec {
    fn default() -> Self {
        Self {
            memory: default_memory(),
            cpu: default_cpu(),
        }
    }
}

fn default_memory() -> String {
    "256m".to_string()
}
fn default_cpu() -> String {
    "0.5".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host: u16,
    pub container: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub host_path: String,
    pub container_path: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RitmaAgentSpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_tier")]
    pub tier: u8,
    #[serde(default)]
    pub capture: Vec<CaptureType>,
    #[serde(default)]
    pub custom_events: Vec<String>,
}

impl Default for RitmaAgentSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            tier: 1,
            capture: vec![CaptureType::ApplicationLogs],
            custom_events: vec![],
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_tier() -> u8 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureType {
    HttpAccessLogs,
    ApplicationLogs,
    ProcessExec,
    ProcessExit,
    FileAccess,
    NetworkFlows,
    DnsQueries,
    DatabaseQueries,
    InferenceEvents,
    Custom(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkloadSpec {
    #[serde(rename = "type", default)]
    pub workload_type: Option<String>,
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSpec {
    pub name: String,
    #[serde(default = "default_driver")]
    pub driver: String,
    pub nodes: Vec<String>,
    #[serde(default)]
    pub subnet: Option<String>,
}

fn default_driver() -> String {
    "bridge".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorSpec {
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u32,
    #[serde(default = "default_export_path")]
    pub export_path: String,
    #[serde(default = "default_chain_algorithm")]
    pub chain_algorithm: String,
}

impl Default for AggregatorSpec {
    fn default() -> Self {
        Self {
            window_seconds: default_window_seconds(),
            export_path: default_export_path(),
            chain_algorithm: default_chain_algorithm(),
        }
    }
}

fn default_window_seconds() -> u32 {
    5
}
fn default_export_path() -> String {
    "./output".to_string()
}
fn default_chain_algorithm() -> String {
    "sha256".to_string()
}

impl Topology {
    pub fn validate(&self) -> Result<(), String> {
        let mut seen_ids = std::collections::HashSet::new();
        for node in &self.nodes {
            if !seen_ids.insert(&node.id) {
                return Err(format!("Duplicate node ID: {}", node.id));
            }
        }

        for network in &self.networks {
            for node_id in &network.nodes {
                if !seen_ids.contains(node_id) {
                    return Err(format!(
                        "Network {} references unknown node: {}",
                        network.name, node_id
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn get_node(&self, id: &str) -> Option<&NodeSpec> {
        self.nodes.iter().find(|n| n.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topology_parse() {
        let yaml = r#"
version: "1.0"
metadata:
  name: test-topology
  seed: 42
nodes:
  - id: node-a
    role: frontend
    resources:
      memory: "256m"
      cpu: "0.5"
  - id: node-b
    role: backend
networks:
  - name: lab-net
    nodes: [node-a, node-b]
aggregator:
  window_seconds: 5
"#;
        let topo: Topology = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(topo.metadata.name, "test-topology");
        assert_eq!(topo.nodes.len(), 2);
        assert!(topo.validate().is_ok());
    }
}
