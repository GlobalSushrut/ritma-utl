//! One-Command Adjacent Runtime Investigation
//!
//! Capability #4: Show adjacent runtime context with:
//! - Neighborhood expansion (related processes, files, network)
//! - Blast radius analysis (what was affected)
//! - Timeline view (temporal context)
//! - Causal chain reconstruction

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

// ============================================================================
// Investigation Context
// ============================================================================

/// Investigation scope and parameters
#[derive(Debug, Clone)]
pub struct InvestigationScope {
    /// Starting point (event ID, process ID, file path, etc.)
    pub anchor: InvestigationAnchor,
    /// Time window (start, end) in unix seconds
    pub time_window: (i64, i64),
    /// Maximum depth for graph traversal
    pub max_depth: u32,
    /// Maximum nodes to include
    pub max_nodes: usize,
    /// Include network connections
    pub include_network: bool,
    /// Include file operations
    pub include_files: bool,
    /// Include child processes
    pub include_children: bool,
    /// Include parent processes
    pub include_parents: bool,
}

impl Default for InvestigationScope {
    fn default() -> Self {
        Self {
            anchor: InvestigationAnchor::EventId("".to_string()),
            time_window: (0, i64::MAX),
            max_depth: 5,
            max_nodes: 1000,
            include_network: true,
            include_files: true,
            include_children: true,
            include_parents: true,
        }
    }
}

/// Starting point for investigation
#[derive(Debug, Clone)]
pub enum InvestigationAnchor {
    /// Start from a specific event
    EventId(String),
    /// Start from a process
    ProcessId(i64),
    /// Start from a file path
    FilePath(String),
    /// Start from a network endpoint
    NetworkEndpoint(String),
    /// Start from a user
    UserId(i64),
    /// Start from a container
    ContainerId(String),
}

// ============================================================================
// Investigation Graph
// ============================================================================

/// Node in the investigation graph
#[derive(Debug, Clone)]
pub struct InvestigationNode {
    /// Unique node ID
    pub node_id: String,
    /// Node type
    pub node_type: NodeType,
    /// Display label
    pub label: String,
    /// Properties
    pub properties: BTreeMap<String, String>,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f64,
    /// Depth from anchor
    pub depth: u32,
    /// Timestamps of activity
    pub timestamps: Vec<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeType {
    Process,
    File,
    NetworkConnection,
    User,
    Container,
    Service,
    Event,
}

impl NodeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::File => "file",
            Self::NetworkConnection => "network",
            Self::User => "user",
            Self::Container => "container",
            Self::Service => "service",
            Self::Event => "event",
        }
    }
}

/// Edge in the investigation graph
#[derive(Debug, Clone)]
pub struct InvestigationEdge {
    /// Source node ID
    pub source: String,
    /// Target node ID
    pub target: String,
    /// Edge type
    pub edge_type: EdgeType,
    /// Timestamp of the relationship
    pub timestamp: i64,
    /// Properties
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    /// Process spawned another process
    Spawned,
    /// Process opened/read/wrote file
    FileAccess,
    /// Process made network connection
    NetworkConnect,
    /// Process executed binary
    Executed,
    /// User owns process
    Owns,
    /// Container contains process
    Contains,
    /// Causal dependency
    CausedBy,
    /// Temporal sequence
    FollowedBy,
}

impl EdgeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Spawned => "spawned",
            Self::FileAccess => "file_access",
            Self::NetworkConnect => "network_connect",
            Self::Executed => "executed",
            Self::Owns => "owns",
            Self::Contains => "contains",
            Self::CausedBy => "caused_by",
            Self::FollowedBy => "followed_by",
        }
    }
}

/// Complete investigation graph
#[derive(Debug, Clone)]
pub struct InvestigationGraph {
    /// All nodes
    pub nodes: HashMap<String, InvestigationNode>,
    /// All edges
    pub edges: Vec<InvestigationEdge>,
    /// Anchor node ID
    pub anchor_id: String,
    /// Investigation scope used
    pub scope: InvestigationScope,
}

impl InvestigationGraph {
    pub fn new(anchor_id: String, scope: InvestigationScope) -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            anchor_id,
            scope,
        }
    }

    pub fn add_node(&mut self, node: InvestigationNode) {
        self.nodes.insert(node.node_id.clone(), node);
    }

    pub fn add_edge(&mut self, edge: InvestigationEdge) {
        self.edges.push(edge);
    }

    /// Get nodes at a specific depth
    pub fn nodes_at_depth(&self, depth: u32) -> Vec<&InvestigationNode> {
        self.nodes.values().filter(|n| n.depth == depth).collect()
    }

    /// Get neighbors of a node
    pub fn neighbors(&self, node_id: &str) -> Vec<&InvestigationNode> {
        let neighbor_ids: HashSet<_> = self
            .edges
            .iter()
            .filter_map(|e| {
                if e.source == node_id {
                    Some(e.target.as_str())
                } else if e.target == node_id {
                    Some(e.source.as_str())
                } else {
                    None
                }
            })
            .collect();

        self.nodes
            .values()
            .filter(|n| neighbor_ids.contains(n.node_id.as_str()))
            .collect()
    }

    /// Calculate blast radius (nodes affected by anchor)
    pub fn blast_radius(&self) -> BlastRadius {
        let mut affected_processes = 0;
        let mut affected_files = 0;
        let mut affected_network = 0;
        let mut affected_users = HashSet::new();
        let mut affected_containers = HashSet::new();
        let mut max_depth = 0;

        for node in self.nodes.values() {
            max_depth = max_depth.max(node.depth);
            match node.node_type {
                NodeType::Process => affected_processes += 1,
                NodeType::File => affected_files += 1,
                NodeType::NetworkConnection => affected_network += 1,
                NodeType::User => {
                    affected_users.insert(node.node_id.clone());
                }
                NodeType::Container => {
                    affected_containers.insert(node.node_id.clone());
                }
                _ => {}
            }
        }

        BlastRadius {
            total_nodes: self.nodes.len(),
            total_edges: self.edges.len(),
            affected_processes,
            affected_files,
            affected_network,
            affected_users: affected_users.len(),
            affected_containers: affected_containers.len(),
            max_depth,
            risk_score: self.calculate_risk_score(),
        }
    }

    fn calculate_risk_score(&self) -> f64 {
        if self.nodes.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.nodes.values().map(|n| n.risk_score).sum();
        (sum / self.nodes.len() as f64).min(1.0)
    }

    /// Get timeline of events
    pub fn timeline(&self) -> Vec<TimelineEntry> {
        let mut entries: Vec<TimelineEntry> = self
            .nodes
            .values()
            .flat_map(|n| {
                n.timestamps.iter().map(move |&ts| TimelineEntry {
                    timestamp: ts,
                    node_id: n.node_id.clone(),
                    node_type: n.node_type,
                    label: n.label.clone(),
                    depth: n.depth,
                })
            })
            .collect();

        entries.sort_by_key(|e| e.timestamp);
        entries
    }
}

/// Blast radius summary
#[derive(Debug, Clone)]
pub struct BlastRadius {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub affected_processes: usize,
    pub affected_files: usize,
    pub affected_network: usize,
    pub affected_users: usize,
    pub affected_containers: usize,
    pub max_depth: u32,
    pub risk_score: f64,
}

impl BlastRadius {
    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "blast-radius@0.1",
            self.total_nodes,
            self.total_edges,
            self.affected_processes,
            self.affected_files,
            self.affected_network,
            self.affected_users,
            self.affected_containers,
            self.max_depth,
            self.risk_score,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

/// Timeline entry
#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub timestamp: i64,
    pub node_id: String,
    pub node_type: NodeType,
    pub label: String,
    pub depth: u32,
}

// ============================================================================
// Neighborhood Expansion
// ============================================================================

/// Neighborhood expansion result
#[derive(Debug, Clone)]
pub struct Neighborhood {
    /// Central node
    pub center: InvestigationNode,
    /// Parent processes
    pub parents: Vec<InvestigationNode>,
    /// Child processes
    pub children: Vec<InvestigationNode>,
    /// Files accessed
    pub files: Vec<InvestigationNode>,
    /// Network connections
    pub network: Vec<InvestigationNode>,
    /// Related users
    pub users: Vec<InvestigationNode>,
    /// Related containers
    pub containers: Vec<InvestigationNode>,
}

impl Neighborhood {
    pub fn new(center: InvestigationNode) -> Self {
        Self {
            center,
            parents: Vec::new(),
            children: Vec::new(),
            files: Vec::new(),
            network: Vec::new(),
            users: Vec::new(),
            containers: Vec::new(),
        }
    }

    /// Total related entities
    pub fn total_related(&self) -> usize {
        self.parents.len()
            + self.children.len()
            + self.files.len()
            + self.network.len()
            + self.users.len()
            + self.containers.len()
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let center = (
            &self.center.node_id,
            &self.center.label,
            self.center.node_type.as_str(),
        );
        let parents: Vec<_> = self
            .parents
            .iter()
            .map(|n| (&n.node_id, &n.label))
            .collect();
        let children: Vec<_> = self
            .children
            .iter()
            .map(|n| (&n.node_id, &n.label))
            .collect();
        let files: Vec<_> = self.files.iter().map(|n| (&n.node_id, &n.label)).collect();
        let network: Vec<_> = self
            .network
            .iter()
            .map(|n| (&n.node_id, &n.label))
            .collect();

        let tuple = (
            "neighborhood@0.1",
            center,
            parents,
            children,
            files,
            network,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Investigation Report
// ============================================================================

/// Complete investigation report
#[derive(Debug, Clone)]
pub struct InvestigationReport {
    /// Report ID
    pub report_id: String,
    /// Timestamp
    pub created_at: String,
    /// Investigation scope
    pub scope: InvestigationScope,
    /// Full graph
    pub graph: InvestigationGraph,
    /// Blast radius summary
    pub blast_radius: BlastRadius,
    /// Timeline
    pub timeline: Vec<TimelineEntry>,
    /// Key findings
    pub findings: Vec<Finding>,
    /// Recommendations
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Finding {
    /// Finding ID
    pub finding_id: String,
    /// Severity
    pub severity: FindingSeverity,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Related node IDs
    pub related_nodes: Vec<String>,
    /// Evidence references
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl InvestigationReport {
    pub fn new(scope: InvestigationScope, graph: InvestigationGraph) -> Self {
        let now = chrono::Utc::now();
        let report_id = {
            let mut h = Sha256::new();
            h.update(b"investigation-report@0.1");
            h.update(now.to_rfc3339().as_bytes());
            h.update(&graph.anchor_id.as_bytes());
            format!("inv-{}", hex::encode(&h.finalize()[..16]))
        };

        let blast_radius = graph.blast_radius();
        let timeline = graph.timeline();

        Self {
            report_id,
            created_at: now.to_rfc3339(),
            scope,
            graph,
            blast_radius,
            timeline,
            findings: Vec::new(),
            recommendations: Vec::new(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn add_recommendation(&mut self, rec: String) {
        self.recommendations.push(rec);
    }

    /// Generate automatic findings based on graph analysis
    pub fn generate_findings(&mut self) {
        // High blast radius
        if self.blast_radius.total_nodes > 100 {
            self.add_finding(Finding {
                finding_id: format!("f-{}", self.findings.len() + 1),
                severity: FindingSeverity::High,
                title: "Large Blast Radius".to_string(),
                description: format!(
                    "Investigation reveals {} affected nodes across {} edges",
                    self.blast_radius.total_nodes, self.blast_radius.total_edges
                ),
                related_nodes: Vec::new(),
                evidence: Vec::new(),
            });
        }

        // Multiple containers affected
        if self.blast_radius.affected_containers > 1 {
            self.add_finding(Finding {
                finding_id: format!("f-{}", self.findings.len() + 1),
                severity: FindingSeverity::Medium,
                title: "Cross-Container Impact".to_string(),
                description: format!(
                    "{} containers affected by this activity",
                    self.blast_radius.affected_containers
                ),
                related_nodes: Vec::new(),
                evidence: Vec::new(),
            });
        }

        // High risk score
        if self.blast_radius.risk_score > 0.7 {
            self.add_finding(Finding {
                finding_id: format!("f-{}", self.findings.len() + 1),
                severity: FindingSeverity::Critical,
                title: "High Risk Activity".to_string(),
                description: format!(
                    "Aggregate risk score of {:.2} exceeds threshold",
                    self.blast_radius.risk_score
                ),
                related_nodes: Vec::new(),
                evidence: Vec::new(),
            });
        }

        // Network activity
        if self.blast_radius.affected_network > 10 {
            self.add_finding(Finding {
                finding_id: format!("f-{}", self.findings.len() + 1),
                severity: FindingSeverity::Medium,
                title: "Significant Network Activity".to_string(),
                description: format!(
                    "{} network connections associated with this activity",
                    self.blast_radius.affected_network
                ),
                related_nodes: Vec::new(),
                evidence: Vec::new(),
            });
        }
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let findings: Vec<_> = self
            .findings
            .iter()
            .map(|f| (&f.finding_id, f.severity.as_str(), &f.title, &f.description))
            .collect();

        let tuple = (
            "investigation-report@0.1",
            &self.report_id,
            &self.created_at,
            self.graph.nodes.len(),
            self.graph.edges.len(),
            self.blast_radius.risk_score,
            findings,
            &self.recommendations,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Investigation Builder
// ============================================================================

/// Builder for constructing investigation graphs
pub struct InvestigationBuilder {
    scope: InvestigationScope,
    nodes: HashMap<String, InvestigationNode>,
    edges: Vec<InvestigationEdge>,
    anchor_id: Option<String>,
    visited: HashSet<String>,
}

impl InvestigationBuilder {
    pub fn new(scope: InvestigationScope) -> Self {
        Self {
            scope,
            nodes: HashMap::new(),
            edges: Vec::new(),
            anchor_id: None,
            visited: HashSet::new(),
        }
    }

    /// Set the anchor node
    pub fn set_anchor(&mut self, node: InvestigationNode) {
        self.anchor_id = Some(node.node_id.clone());
        self.visited.insert(node.node_id.clone());
        self.nodes.insert(node.node_id.clone(), node);
    }

    /// Add a related node
    pub fn add_node(&mut self, node: InvestigationNode) -> bool {
        if self.nodes.len() >= self.scope.max_nodes {
            return false;
        }
        if node.depth > self.scope.max_depth {
            return false;
        }
        if self.visited.contains(&node.node_id) {
            return false;
        }
        self.visited.insert(node.node_id.clone());
        self.nodes.insert(node.node_id.clone(), node);
        true
    }

    /// Add an edge
    pub fn add_edge(&mut self, edge: InvestigationEdge) {
        self.edges.push(edge);
    }

    /// Build the investigation graph
    pub fn build(self) -> InvestigationGraph {
        let anchor_id = self.anchor_id.unwrap_or_default();
        let mut graph = InvestigationGraph::new(anchor_id, self.scope);
        graph.nodes = self.nodes;
        graph.edges = self.edges;
        graph
    }

    /// Create a process node
    pub fn process_node(pid: i64, comm: &str, depth: u32) -> InvestigationNode {
        let node_id = format!("proc-{}", pid);
        let mut props = BTreeMap::new();
        props.insert("pid".to_string(), pid.to_string());
        props.insert("comm".to_string(), comm.to_string());

        InvestigationNode {
            node_id,
            node_type: NodeType::Process,
            label: format!("{}({})", comm, pid),
            properties: props,
            risk_score: 0.0,
            depth,
            timestamps: Vec::new(),
        }
    }

    /// Create a file node
    pub fn file_node(path: &str, depth: u32) -> InvestigationNode {
        let mut h = Sha256::new();
        h.update(path.as_bytes());
        let node_id = format!("file-{}", hex::encode(&h.finalize()[..8]));

        let mut props = BTreeMap::new();
        props.insert("path".to_string(), path.to_string());

        InvestigationNode {
            node_id,
            node_type: NodeType::File,
            label: path.rsplit('/').next().unwrap_or(path).to_string(),
            properties: props,
            risk_score: 0.0,
            depth,
            timestamps: Vec::new(),
        }
    }

    /// Create a network node
    pub fn network_node(endpoint: &str, protocol: &str, depth: u32) -> InvestigationNode {
        let mut h = Sha256::new();
        h.update(endpoint.as_bytes());
        let node_id = format!("net-{}", hex::encode(&h.finalize()[..8]));

        let mut props = BTreeMap::new();
        props.insert("endpoint".to_string(), endpoint.to_string());
        props.insert("protocol".to_string(), protocol.to_string());

        InvestigationNode {
            node_id,
            node_type: NodeType::NetworkConnection,
            label: endpoint.to_string(),
            properties: props,
            risk_score: 0.0,
            depth,
            timestamps: Vec::new(),
        }
    }

    /// Create a user node
    pub fn user_node(uid: i64, username: Option<&str>, depth: u32) -> InvestigationNode {
        let node_id = format!("user-{}", uid);
        let mut props = BTreeMap::new();
        props.insert("uid".to_string(), uid.to_string());
        if let Some(name) = username {
            props.insert("username".to_string(), name.to_string());
        }

        InvestigationNode {
            node_id,
            node_type: NodeType::User,
            label: username.unwrap_or(&uid.to_string()).to_string(),
            properties: props,
            risk_score: 0.0,
            depth,
            timestamps: Vec::new(),
        }
    }

    /// Create a container node
    pub fn container_node(container_id: &str, depth: u32) -> InvestigationNode {
        let node_id = format!("ctr-{}", &container_id[..12.min(container_id.len())]);
        let mut props = BTreeMap::new();
        props.insert("container_id".to_string(), container_id.to_string());

        InvestigationNode {
            node_id,
            node_type: NodeType::Container,
            label: container_id[..12.min(container_id.len())].to_string(),
            properties: props,
            risk_score: 0.0,
            depth,
            timestamps: Vec::new(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_investigation_graph() {
        let scope = InvestigationScope::default();
        let mut builder = InvestigationBuilder::new(scope.clone());

        // Create anchor process
        let mut anchor = InvestigationBuilder::process_node(1234, "malware", 0);
        anchor.risk_score = 0.9;
        anchor.timestamps.push(1700000000);
        builder.set_anchor(anchor);

        // Add child process
        let mut child = InvestigationBuilder::process_node(1235, "shell", 1);
        child.timestamps.push(1700000001);
        builder.add_node(child);

        // Add file access
        let mut file = InvestigationBuilder::file_node("/etc/passwd", 1);
        file.timestamps.push(1700000002);
        builder.add_node(file);

        // Add edges
        builder.add_edge(InvestigationEdge {
            source: "proc-1234".to_string(),
            target: "proc-1235".to_string(),
            edge_type: EdgeType::Spawned,
            timestamp: 1700000001,
            properties: BTreeMap::new(),
        });

        let graph = builder.build();

        assert_eq!(graph.nodes.len(), 3);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.anchor_id, "proc-1234");
    }

    #[test]
    fn test_blast_radius() {
        let scope = InvestigationScope::default();
        let mut builder = InvestigationBuilder::new(scope.clone());

        builder.set_anchor(InvestigationBuilder::process_node(1, "init", 0));
        builder.add_node(InvestigationBuilder::process_node(2, "child1", 1));
        builder.add_node(InvestigationBuilder::process_node(3, "child2", 1));
        builder.add_node(InvestigationBuilder::file_node("/tmp/test", 2));
        builder.add_node(InvestigationBuilder::network_node("1.2.3.4:80", "tcp", 2));

        let graph = builder.build();
        let blast = graph.blast_radius();

        assert_eq!(blast.total_nodes, 5);
        assert_eq!(blast.affected_processes, 3);
        assert_eq!(blast.affected_files, 1);
        assert_eq!(blast.affected_network, 1);
        assert_eq!(blast.max_depth, 2);
    }

    #[test]
    fn test_timeline() {
        let scope = InvestigationScope::default();
        let mut builder = InvestigationBuilder::new(scope.clone());

        let mut p1 = InvestigationBuilder::process_node(1, "first", 0);
        p1.timestamps.push(1000);
        builder.set_anchor(p1);

        let mut p2 = InvestigationBuilder::process_node(2, "second", 1);
        p2.timestamps.push(2000);
        builder.add_node(p2);

        let mut p3 = InvestigationBuilder::process_node(3, "third", 1);
        p3.timestamps.push(1500);
        builder.add_node(p3);

        let graph = builder.build();
        let timeline = graph.timeline();

        assert_eq!(timeline.len(), 3);
        assert_eq!(timeline[0].timestamp, 1000);
        assert_eq!(timeline[1].timestamp, 1500);
        assert_eq!(timeline[2].timestamp, 2000);
    }

    #[test]
    fn test_investigation_report() {
        let scope = InvestigationScope::default();
        let mut builder = InvestigationBuilder::new(scope.clone());

        let mut anchor = InvestigationBuilder::process_node(1, "test", 0);
        anchor.risk_score = 0.8;
        builder.set_anchor(anchor);

        let graph = builder.build();
        let mut report = InvestigationReport::new(scope, graph);

        report.generate_findings();
        report.add_recommendation("Isolate affected process".to_string());

        assert!(!report.report_id.is_empty());
        assert!(!report.recommendations.is_empty());

        let cbor = report.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_neighborhood() {
        let center = InvestigationBuilder::process_node(1, "center", 0);
        let mut neighborhood = Neighborhood::new(center);

        neighborhood
            .parents
            .push(InvestigationBuilder::process_node(0, "parent", 1));
        neighborhood
            .children
            .push(InvestigationBuilder::process_node(2, "child", 1));
        neighborhood
            .files
            .push(InvestigationBuilder::file_node("/tmp/test", 1));

        assert_eq!(neighborhood.total_related(), 3);

        let cbor = neighborhood.to_cbor();
        assert!(!cbor.is_empty());
    }
}
