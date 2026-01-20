use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub git_commit: String,
    pub build_hash: String,
    pub build_time: String,
    pub rust_version: String,
    pub target_triple: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: String,
    pub host_fingerprint: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentInfo {
    pub mode: String,
    pub generator_version: String,
    pub config_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub start: String,
    pub end: String,
    pub duration_ms: i64,
    pub window_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceInfo {
    pub namespace_uri: String,
    pub purpose: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorInfo {
    pub operator_id: String,
    pub role: String,
    pub export_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyInfo {
    pub mode: String,
    pub scope_namespace: String,
    pub scope_ttl_hours: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCfg {
    pub enabled: bool,
    pub config_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourcesMatrix {
    pub auditd: SourceCfg,
    pub ebpf: SourceCfg,
    pub proc_scan: SourceCfg,
    pub k8s_audit: SourceCfg,
    pub otel: SourceCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPackManifest {
    pub format_version: String,
    pub schema_id: String,
    pub build_info: BuildInfo,
    pub node: NodeIdentity,
    pub deployment: DeploymentInfo,
    pub window: WindowInfo,
    pub namespace: NamespaceInfo,
    pub operator: OperatorInfo,
    pub policy: PolicyInfo,
    pub privacy: PrivacyInfo,
    pub sources: SourcesMatrix,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip_serde_json() {
        let m = ProofPackManifest {
            format_version: "ritma-proofpack/1.0.0".to_string(),
            schema_id: "schema-1".to_string(),
            build_info: BuildInfo {
                git_commit: "deadbeef".to_string(),
                build_hash: "build".to_string(),
                build_time: "2025-01-01T00:00:00Z".to_string(),
                rust_version: "1.75".to_string(),
                target_triple: "x86_64-unknown-linux-gnu".to_string(),
            },
            node: NodeIdentity {
                node_id: "node-1".to_string(),
                host_fingerprint: "fp".to_string(),
                hostname: "host".to_string(),
            },
            deployment: DeploymentInfo {
                mode: "docker".to_string(),
                generator_version: "ritma_cli/0.1.0".to_string(),
                config_hash: None,
            },
            window: WindowInfo {
                start: "2025-01-01T00:00:00Z".to_string(),
                end: "2025-01-01T01:00:00Z".to_string(),
                duration_ms: 3600_000,
                window_id: "w1".to_string(),
            },
            namespace: NamespaceInfo {
                namespace_uri: "ns://test".to_string(),
                purpose: "Incident".to_string(),
                tags: vec![],
            },
            operator: OperatorInfo {
                operator_id: "system".to_string(),
                role: "System".to_string(),
                export_time: "2025-01-01T02:00:00Z".to_string(),
            },
            policy: PolicyInfo {
                policy_id: "default".to_string(),
                policy_version: "0.2".to_string(),
                policy_hash: None,
            },
            privacy: PrivacyInfo {
                mode: "hash-only".to_string(),
                scope_namespace: "ns://test".to_string(),
                scope_ttl_hours: None,
            },
            sources: SourcesMatrix {
                auditd: SourceCfg {
                    enabled: true,
                    config_hash: None,
                },
                ebpf: SourceCfg {
                    enabled: true,
                    config_hash: None,
                },
                proc_scan: SourceCfg {
                    enabled: true,
                    config_hash: None,
                },
                k8s_audit: SourceCfg {
                    enabled: false,
                    config_hash: None,
                },
                otel: SourceCfg {
                    enabled: false,
                    config_hash: None,
                },
            },
        };

        let s = serde_json::to_string(&m).unwrap();
        let m2: ProofPackManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(m2.format_version, "ritma-proofpack/1.0.0");
        assert_eq!(m2.namespace.namespace_uri, "ns://test");
        assert!(m2.namespace.tags.is_empty());
    }
}
