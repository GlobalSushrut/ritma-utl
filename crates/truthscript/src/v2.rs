// TruthScript v2 - Infrastructure-Aware Universal Policy Language
// Designed for Ritma's DID-based, mTLS, eBPF, cgroup, and distributed architecture

use crate::{Policy as V1Policy, PolicyHeader, Rule as V1Rule};
use serde::{Deserialize, Serialize};

/// TruthScript v2 Policy with infrastructure awareness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyV2 {
    /// Enhanced header with v2 metadata
    pub header: PolicyHeader,

    /// Infrastructure context requirements
    #[serde(default)]
    pub infra_context: InfraContext,

    /// v2 rules with infrastructure primitives
    pub rules: Vec<RuleV2>,

    /// Backward compatibility: can import v1 rules
    #[serde(default)]
    pub legacy_rules: Vec<V1Rule>,
}

/// Infrastructure context for policy execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InfraContext {
    /// Required infrastructure capabilities
    #[serde(default)]
    pub required_capabilities: Vec<InfraCapability>,

    /// Execution environment (local, distributed, consensus)
    #[serde(default)]
    pub execution_mode: ExecutionMode,

    /// DID-based identity requirements
    #[serde(default)]
    pub identity_requirements: IdentityRequirements,

    /// Resource limits and quotas
    #[serde(default)]
    pub resource_limits: ResourceLimits,
}

/// Infrastructure capabilities required by policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InfraCapability {
    /// eBPF XDP packet filtering
    EbpfXdp,
    /// Cgroup resource isolation
    Cgroups,
    /// mTLS with client certificates
    Mtls,
    /// DID-based identity
    DidIdentity,
    /// Distributed consensus
    Consensus,
    /// zkSNARK proofs
    ZkProofs,
    /// Merkle tree evidence
    MerkleEvidence,
}

/// Policy execution mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    /// Single node execution
    #[default]
    Local,
    /// Multi-node with consensus
    Distributed,
    /// Consensus required for decisions
    ConsensusRequired,
}

/// DID-based identity requirements
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityRequirements {
    /// Require mTLS client certificate
    #[serde(default)]
    pub require_mtls: bool,

    /// Required DID prefixes (e.g., "did:ritma:tenant:")
    #[serde(default)]
    pub required_did_prefixes: Vec<String>,

    /// Allowed DID patterns
    #[serde(default)]
    pub allowed_did_patterns: Vec<String>,

    /// Require DID signature verification
    #[serde(default)]
    pub require_signature: bool,
}

/// Resource limits for policy enforcement
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceLimits {
    /// Max CPU percentage (cgroup)
    #[serde(default)]
    pub max_cpu_percent: Option<u32>,

    /// Max memory in MB (cgroup)
    #[serde(default)]
    pub max_memory_mb: Option<u64>,

    /// Max network bandwidth in Mbps
    #[serde(default)]
    pub max_network_mbps: Option<u32>,

    /// Max concurrent connections
    #[serde(default)]
    pub max_connections: Option<u32>,
}

/// TruthScript v2 Rule with infrastructure primitives
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleV2 {
    pub name: String,

    /// v2 when clause with infrastructure conditions
    #[serde(default)]
    pub when: Option<WhenV2>,

    /// v2 actions with infrastructure operations
    #[serde(default)]
    pub actions: Vec<ActionV2>,

    /// Rule priority (higher = evaluated first)
    #[serde(default)]
    pub priority: i32,

    /// Rule scope (tenant, zone, global)
    #[serde(default)]
    pub scope: RuleScope,
}

/// Rule scope for multi-tenant isolation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleScope {
    /// Applies to specific tenant
    Tenant(String),
    /// Applies to network zone
    Zone(String),
    /// Applies globally
    #[default]
    Global,
}

/// v2 When clause with infrastructure conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhenV2 {
    /// Event selector
    #[serde(default)]
    pub event: Option<String>,

    /// v2 conditions with infrastructure primitives
    #[serde(default)]
    pub conditions: Vec<ConditionV2>,

    /// Logical operator (all, any, none)
    #[serde(default)]
    pub operator: LogicalOperator,
}

/// Logical operators for combining conditions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogicalOperator {
    /// All conditions must match (AND)
    #[default]
    All,
    /// Any condition must match (OR)
    Any,
    /// No conditions must match (NOT)
    None,
}

/// v2 Conditions with infrastructure awareness
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConditionV2 {
    // Legacy v1 conditions
    EventEquals {
        value: String,
    },
    FieldEquals {
        field: String,
        value: String,
    },
    FieldGreaterThan {
        field: String,
        threshold: f64,
    },

    // DID-based conditions
    DidEquals {
        did: String,
    },
    DidPrefix {
        prefix: String,
    },
    DidPattern {
        pattern: String,
    },
    DidInZone {
        zone: String,
    },
    DidHasClaim {
        claim: String,
        value: Option<String>,
    },

    // mTLS conditions
    MtlsVerified,
    MtlsCertValid,
    MtlsCertIssuer {
        issuer: String,
    },

    // Network conditions
    SourceIp {
        ip: String,
    },
    SourceIpInRange {
        cidr: String,
    },
    DestinationPort {
        port: u16,
    },
    Protocol {
        protocol: String,
    },

    // Resource conditions (cgroup)
    CpuUsageAbove {
        percent: u32,
    },
    MemoryUsageAbove {
        mb: u64,
    },
    CgroupExists {
        path: String,
    },

    // eBPF conditions
    EbpfMapHasKey {
        map_path: String,
        key: String,
    },
    EbpfDecision {
        decision: String,
    },
    PacketDropped,

    // Consensus conditions
    ConsensusReached {
        threshold: u32,
    },
    ValidatorCount {
        min: u32,
    },

    // Proof conditions
    ProofValid {
        proof_type: String,
    },
    ProofVerified,
    MerkleIncluded {
        root: String,
    },
}

/// v2 Actions with infrastructure operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionV2 {
    // Legacy v1 actions
    Deny {
        reason: String,
    },
    FlagForInvestigation {
        reason: String,
    },
    CaptureInput,
    CaptureOutput,

    // eBPF actions
    EbpfDrop {
        reason: String,
    },
    EbpfAllow,
    EbpfRateLimit {
        packets_per_sec: u32,
    },
    EbpfUpdateMap {
        map_path: String,
        key: String,
        value: String,
    },

    // Cgroup actions
    CgroupIsolate {
        cgroup_path: String,
    },
    CgroupSetCpuLimit {
        percent: u32,
    },
    CgroupSetMemoryLimit {
        mb: u64,
    },
    CgroupFreeze,
    CgroupUnfreeze,

    // Network actions
    NetworkQuarantine {
        duration_secs: u64,
    },
    NetworkAllowIngress {
        port: u16,
    },
    NetworkAllowEgress {
        destination: String,
    },
    NetworkDenyAll,

    // DID actions
    DidRevoke {
        did: String,
        reason: String,
    },
    DidSuspend {
        did: String,
        duration_secs: u64,
    },
    DidRequireReauth {
        did: String,
    },

    // mTLS actions
    MtlsRequireClientCert,
    MtlsRevokeSession,

    // Consensus actions
    ConsensusRequest {
        validators: Vec<String>,
    },
    ConsensusVote {
        decision: String,
    },

    // Proof actions
    RequireSnarkProof,
    RequireMerkleProof,
    GenerateProof {
        proof_type: String,
    },

    // Evidence actions
    EmitDecisionEvent {
        index: String,
    },
    EmitComplianceRecord {
        framework: String,
    },

    // Service lifecycle
    ServiceStop {
        service_name: String,
    },
    ServiceRestart {
        service_name: String,
    },
    ServiceScale {
        service_name: String,
        replicas: u32,
    },
}

impl PolicyV2 {
    /// Convert v1 policy to v2 (migration helper)
    pub fn from_v1(v1: V1Policy) -> Self {
        let header = v1.header.unwrap_or_else(|| PolicyHeader {
            name: v1.name.clone(),
            version: v1.version.clone(),
            encoding: "UTF-8".to_string(),
            author: None,
            description: None,
            frameworks: vec![],
            policy_hash: None,
            consensus_threshold: None,
            cue_schema: None,
            proof_type: None,
            created_at: None,
            signature: None,
        });

        Self {
            header,
            infra_context: InfraContext::default(),
            rules: vec![],
            legacy_rules: v1.rules,
        }
    }

    /// Validate v2 policy
    pub fn validate(&self) -> Result<(), String> {
        if self.header.name.is_empty() {
            return Err("Policy name is required".to_string());
        }

        if self.header.version.is_empty() {
            return Err("Policy version is required".to_string());
        }

        if self.rules.is_empty() && self.legacy_rules.is_empty() {
            return Err("Policy must have at least one rule".to_string());
        }

        // Validate infrastructure context
        if self.infra_context.execution_mode == ExecutionMode::ConsensusRequired
            && self.header.consensus_threshold.is_none()
        {
            return Err("Consensus threshold required for ConsensusRequired mode".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_v2_validates() {
        let policy = PolicyV2 {
            header: PolicyHeader {
                name: "test_policy".to_string(),
                version: "2.0.0".to_string(),
                encoding: "UTF-8".to_string(),
                author: Some("Ritma".to_string()),
                description: Some("Test v2 policy".to_string()),
                frameworks: vec!["SOC2".to_string()],
                policy_hash: None,
                consensus_threshold: Some(2),
                cue_schema: None,
                proof_type: Some("snark".to_string()),
                created_at: None,
                signature: None,
            },
            infra_context: InfraContext {
                required_capabilities: vec![
                    InfraCapability::EbpfXdp,
                    InfraCapability::Mtls,
                    InfraCapability::DidIdentity,
                ],
                execution_mode: ExecutionMode::Distributed,
                identity_requirements: IdentityRequirements {
                    require_mtls: true,
                    required_did_prefixes: vec!["did:ritma:tenant:".to_string()],
                    allowed_did_patterns: vec![],
                    require_signature: true,
                },
                resource_limits: ResourceLimits {
                    max_cpu_percent: Some(80),
                    max_memory_mb: Some(1024),
                    max_network_mbps: Some(100),
                    max_connections: Some(1000),
                },
            },
            rules: vec![RuleV2 {
                name: "block_high_threat".to_string(),
                when: Some(WhenV2 {
                    event: Some("network_request".to_string()),
                    conditions: vec![
                        ConditionV2::FieldGreaterThan {
                            field: "threat_score".to_string(),
                            threshold: 0.8,
                        },
                        ConditionV2::MtlsVerified,
                    ],
                    operator: LogicalOperator::All,
                }),
                actions: vec![
                    ActionV2::EbpfDrop {
                        reason: "High threat score".to_string(),
                    },
                    ActionV2::EmitDecisionEvent {
                        index: "security_events".to_string(),
                    },
                ],
                priority: 100,
                scope: RuleScope::Global,
            }],
            legacy_rules: vec![],
        };

        assert!(policy.validate().is_ok());
    }

    #[test]
    fn v2_supports_did_conditions() {
        let condition = ConditionV2::DidPrefix {
            prefix: "did:ritma:tenant:acme".to_string(),
        };

        // Serialize to ensure it works
        let json = serde_json::to_string(&condition).unwrap();
        assert!(json.contains("did_prefix"));
    }

    #[test]
    fn v2_supports_ebpf_actions() {
        let action = ActionV2::EbpfUpdateMap {
            map_path: "/sys/fs/bpf/ritma_fw_pairs".to_string(),
            key: "did_pair_123".to_string(),
            value: "allow".to_string(),
        };

        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("ebpf_update_map"));
    }
}
