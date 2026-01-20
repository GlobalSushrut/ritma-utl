use anyhow::Result;
use std::collections::HashMap;
use ritma_lab_proto::{Topology, NodeSpec, NetworkSpec};

pub struct TopologyManager {
    topology: Topology,
    node_ips: HashMap<String, String>,
}

impl TopologyManager {
    pub fn new(topology: Topology) -> Result<Self> {
        topology.validate().map_err(|e| anyhow::anyhow!(e))?;
        let node_ips = Self::assign_ips(&topology);
        Ok(Self { topology, node_ips })
    }

    fn assign_ips(topology: &Topology) -> HashMap<String, String> {
        let mut ips = HashMap::new();
        let mut next_ip = 2u8;

        for node in &topology.nodes {
            ips.insert(node.id.clone(), format!("172.28.0.{}", next_ip));
            next_ip += 1;
        }

        ips
    }

    pub fn get_node_ip(&self, node_id: &str) -> Option<&String> {
        self.node_ips.get(node_id)
    }

    pub fn get_node(&self, node_id: &str) -> Option<&NodeSpec> {
        self.topology.get_node(node_id)
    }

    pub fn nodes(&self) -> &[NodeSpec] {
        &self.topology.nodes
    }

    pub fn networks(&self) -> &[NetworkSpec] {
        &self.topology.networks
    }

    pub fn topology(&self) -> &Topology {
        &self.topology
    }
}
