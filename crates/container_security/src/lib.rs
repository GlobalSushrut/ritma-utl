use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContainerSecurityError {
    #[error("Container escape detected: {0}")]
    ContainerEscapeError(String),
    #[error("Kubernetes API abuse detected: {0}")]
    K8sApiAbuseError(String),
    #[error("Lateral movement detected: {0}")]
    LateralMovementError(String),
    #[error("Registry poisoning detected: {0}")]
    RegistryPoisoningError(String),
}

pub type Result<T> = std::result::Result<T, ContainerSecurityError>;

/// Container escape alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEscapeAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub container_id: String,
    pub container_name: String,
    pub escape_technique: EscapeTechnique,
    pub severity: Severity,
    pub description: String,
    pub evidence: EscapeEvidence,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscapeTechnique {
    PrivilegedContainer,
    HostPathMount,
    ProcMount,
    SysMount,
    CapabilitiesAbuse,
    CgroupEscape,
    NamespaceEscape,
    DockerSocketMount,
    KernelExploit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscapeEvidence {
    pub privileged: bool,
    pub host_mounts: Vec<String>,
    pub capabilities: Vec<String>,
    pub namespace_violations: Vec<String>,
    pub syscalls_used: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Kubernetes API abuse alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sApiAbuseAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub user: String,
    pub service_account: Option<String>,
    pub abuse_type: K8sAbuseType,
    pub api_calls: Vec<K8sApiCall>,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum K8sAbuseType {
    UnauthorizedSecretAccess,
    PrivilegeEscalation,
    PodCreationAbuse,
    RbacBypass,
    TokenTheft,
    ApiServerExploit,
    EtcdAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sApiCall {
    pub timestamp: String,
    pub verb: String,     // GET, POST, PUT, DELETE, etc.
    pub resource: String, // pods, secrets, configmaps, etc.
    pub namespace: String,
    pub name: Option<String>,
    pub response_code: u16,
}

/// Pod-to-pod lateral movement alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub source_pod: String,
    pub source_namespace: String,
    pub target_pod: String,
    pub target_namespace: String,
    pub movement_type: MovementType,
    pub network_connections: Vec<NetworkConnection>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MovementType {
    CrossNamespace,
    ServiceAccountAbuse,
    NetworkPolicyBypass,
    ContainerToHost,
    PodExec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub timestamp: String,
    pub source_ip: String,
    pub source_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    pub bytes_sent: usize,
}

/// Registry poisoning alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPoisoningAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub registry: String,
    pub image_name: String,
    pub image_tag: String,
    pub poisoning_type: PoisoningType,
    pub severity: Severity,
    pub evidence: PoisoningEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PoisoningType {
    MaliciousLayer,
    BackdoorInjection,
    SupplyChainAttack,
    TagMutation,
    DigestMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoisoningEvidence {
    pub expected_digest: String,
    pub actual_digest: String,
    pub suspicious_layers: Vec<String>,
    pub malicious_files: Vec<String>,
}

/// Container escape detector
pub struct ContainerEscapeDetector {
    /// Tracked containers
    containers: HashMap<String, ContainerInfo>,

    /// Escape alerts
    alerts: Vec<ContainerEscapeAlert>,
}

#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub container_id: String,
    pub container_name: String,
    pub privileged: bool,
    pub host_mounts: Vec<String>,
    pub capabilities: Vec<String>,
    pub pid_namespace: String,
    pub network_namespace: String,
}

impl ContainerEscapeDetector {
    pub fn new() -> Self {
        Self {
            containers: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Register a container for monitoring
    pub fn register_container(&mut self, info: ContainerInfo) {
        log::info!("Registering container: {}", info.container_id);
        self.containers.insert(info.container_id.clone(), info);
    }

    /// Check for container escape attempts
    pub fn check_escape_attempts(&mut self, container_id: &str) -> Vec<ContainerEscapeAlert> {
        let mut new_alerts = Vec::new();

        if let Some(info) = self.containers.get(container_id) {
            // Check for privileged container
            if info.privileged {
                let alert = self.create_escape_alert(
                    info,
                    EscapeTechnique::PrivilegedContainer,
                    "Container running in privileged mode - full host access possible",
                );
                new_alerts.push(alert.clone());
                self.alerts.push(alert);
            }

            // Check for dangerous host mounts
            for mount in &info.host_mounts {
                if mount.starts_with("/proc") || mount.starts_with("/sys") || mount == "/" {
                    let alert = self.create_escape_alert(
                        info,
                        if mount.starts_with("/proc") {
                            EscapeTechnique::ProcMount
                        } else if mount.starts_with("/sys") {
                            EscapeTechnique::SysMount
                        } else {
                            EscapeTechnique::HostPathMount
                        },
                        &format!("Dangerous host mount detected: {mount}"),
                    );
                    new_alerts.push(alert.clone());
                    self.alerts.push(alert);
                }
            }

            // Check for Docker socket mount
            if info.host_mounts.iter().any(|m| m.contains("docker.sock")) {
                let alert = self.create_escape_alert(
                    info,
                    EscapeTechnique::DockerSocketMount,
                    "Docker socket mounted - full container orchestration access",
                );
                new_alerts.push(alert.clone());
                self.alerts.push(alert);
            }

            // Check for dangerous capabilities
            let dangerous_caps = ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"];
            for cap in &dangerous_caps {
                if info.capabilities.iter().any(|c| c == cap) {
                    let alert = self.create_escape_alert(
                        info,
                        EscapeTechnique::CapabilitiesAbuse,
                        &format!("Dangerous capability detected: {cap}"),
                    );
                    new_alerts.push(alert.clone());
                    self.alerts.push(alert);
                }
            }
        }

        new_alerts
    }

    fn create_escape_alert(
        &self,
        info: &ContainerInfo,
        technique: EscapeTechnique,
        description: &str,
    ) -> ContainerEscapeAlert {
        ContainerEscapeAlert {
            alert_id: format!("escape_{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            container_id: info.container_id.clone(),
            container_name: info.container_name.clone(),
            escape_technique: technique,
            severity: Severity::Critical,
            description: description.to_string(),
            evidence: EscapeEvidence {
                privileged: info.privileged,
                host_mounts: info.host_mounts.clone(),
                capabilities: info.capabilities.clone(),
                namespace_violations: vec![],
                syscalls_used: vec![],
            },
            recommended_action: "Terminate container immediately, review security policy"
                .to_string(),
        }
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[ContainerEscapeAlert] {
        &self.alerts
    }
}

impl Default for ContainerEscapeDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Kubernetes API abuse detector
pub struct K8sApiAbuseDetector {
    /// API call history by user
    api_calls: HashMap<String, Vec<K8sApiCall>>,

    /// Abuse alerts
    alerts: Vec<K8sApiAbuseAlert>,

    /// Suspicious patterns
    suspicious_threshold: usize,
}

impl K8sApiAbuseDetector {
    pub fn new(suspicious_threshold: usize) -> Self {
        Self {
            api_calls: HashMap::new(),
            alerts: Vec::new(),
            suspicious_threshold,
        }
    }

    /// Record an API call
    pub fn record_api_call(&mut self, user: String, call: K8sApiCall) {
        self.api_calls.entry(user).or_default().push(call);
    }

    /// Analyze API calls for abuse
    pub fn analyze_abuse(&mut self, user: &str) -> Vec<K8sApiAbuseAlert> {
        let mut new_alerts = Vec::new();

        if let Some(calls) = self.api_calls.get(user) {
            // Check for secret access
            let secret_accesses: Vec<_> = calls
                .iter()
                .filter(|c| c.resource == "secrets" && c.verb == "GET")
                .collect();

            if secret_accesses.len() > self.suspicious_threshold {
                let alert = K8sApiAbuseAlert {
                    alert_id: format!("k8s_abuse_{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    user: user.to_string(),
                    service_account: None,
                    abuse_type: K8sAbuseType::UnauthorizedSecretAccess,
                    api_calls: secret_accesses.into_iter().cloned().collect(),
                    severity: Severity::Critical,
                    description: format!("Excessive secret access by user: {user}"),
                };
                new_alerts.push(alert.clone());
                self.alerts.push(alert);
            }

            // Check for privilege escalation attempts
            let priv_esc: Vec<_> = calls
                .iter()
                .filter(|c| {
                    (c.resource == "roles" || c.resource == "clusterroles")
                        && (c.verb == "CREATE" || c.verb == "UPDATE")
                })
                .collect();

            if !priv_esc.is_empty() {
                let alert = K8sApiAbuseAlert {
                    alert_id: format!("k8s_abuse_{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    user: user.to_string(),
                    service_account: None,
                    abuse_type: K8sAbuseType::PrivilegeEscalation,
                    api_calls: priv_esc.into_iter().cloned().collect(),
                    severity: Severity::Critical,
                    description: format!("Privilege escalation attempt by user: {user}"),
                };
                new_alerts.push(alert.clone());
                self.alerts.push(alert);
            }
        }

        new_alerts
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[K8sApiAbuseAlert] {
        &self.alerts
    }
}

/// Lateral movement detector
pub struct LateralMovementDetector {
    /// Pod network connections
    pod_connections: HashMap<String, Vec<NetworkConnection>>,

    /// Lateral movement alerts
    alerts: Vec<LateralMovementAlert>,
}

impl LateralMovementDetector {
    pub fn new() -> Self {
        Self {
            pod_connections: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Record a network connection
    pub fn record_connection(&mut self, pod_id: String, conn: NetworkConnection) {
        self.pod_connections.entry(pod_id).or_default().push(conn);
    }

    /// Detect lateral movement
    pub fn detect_lateral_movement(
        &mut self,
        source_pod: &str,
        source_namespace: &str,
        target_namespace: &str,
    ) -> Option<LateralMovementAlert> {
        // Cross-namespace communication is suspicious
        if source_namespace != target_namespace {
            let connections = self
                .pod_connections
                .get(source_pod)
                .cloned()
                .unwrap_or_default();

            let alert = LateralMovementAlert {
                alert_id: format!("lateral_{}", uuid::Uuid::new_v4()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                source_pod: source_pod.to_string(),
                source_namespace: source_namespace.to_string(),
                target_pod: "unknown".to_string(),
                target_namespace: target_namespace.to_string(),
                movement_type: MovementType::CrossNamespace,
                network_connections: connections,
                severity: Severity::High,
            };

            log::warn!("Lateral movement detected: {source_namespace} -> {target_namespace}");
            self.alerts.push(alert.clone());
            return Some(alert);
        }

        None
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[LateralMovementAlert] {
        &self.alerts
    }
}

impl Default for LateralMovementDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry poisoning detector
pub struct RegistryPoisoningDetector {
    /// Known good image digests
    trusted_digests: HashMap<String, String>,

    /// Poisoning alerts
    alerts: Vec<RegistryPoisoningAlert>,
}

impl RegistryPoisoningDetector {
    pub fn new() -> Self {
        Self {
            trusted_digests: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Register a trusted image digest
    pub fn register_trusted_image(&mut self, image: String, digest: String) {
        self.trusted_digests.insert(image, digest);
    }

    /// Verify image integrity
    pub fn verify_image(
        &mut self,
        registry: &str,
        image_name: &str,
        image_tag: &str,
        actual_digest: &str,
    ) -> Option<RegistryPoisoningAlert> {
        let image_key = format!("{registry}:{image_name}:{image_tag}");

        if let Some(expected_digest) = self.trusted_digests.get(&image_key) {
            if expected_digest != actual_digest {
                let alert = RegistryPoisoningAlert {
                    alert_id: format!("poison_{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    registry: registry.to_string(),
                    image_name: image_name.to_string(),
                    image_tag: image_tag.to_string(),
                    poisoning_type: PoisoningType::DigestMismatch,
                    severity: Severity::Critical,
                    evidence: PoisoningEvidence {
                        expected_digest: expected_digest.clone(),
                        actual_digest: actual_digest.to_string(),
                        suspicious_layers: vec![],
                        malicious_files: vec![],
                    },
                };

                log::error!(
                    "Registry poisoning detected: {image_key} (expected: {expected_digest}, actual: {actual_digest})"
                );
                self.alerts.push(alert.clone());
                return Some(alert);
            }
        }

        None
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[RegistryPoisoningAlert] {
        &self.alerts
    }
}

impl Default for RegistryPoisoningDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Main container security manager
pub struct ContainerSecurityManager {
    escape_detector: ContainerEscapeDetector,
    k8s_abuse_detector: K8sApiAbuseDetector,
    lateral_movement_detector: LateralMovementDetector,
    registry_poisoning_detector: RegistryPoisoningDetector,
}

impl ContainerSecurityManager {
    pub fn new(suspicious_api_threshold: usize) -> Self {
        Self {
            escape_detector: ContainerEscapeDetector::new(),
            k8s_abuse_detector: K8sApiAbuseDetector::new(suspicious_api_threshold),
            lateral_movement_detector: LateralMovementDetector::new(),
            registry_poisoning_detector: RegistryPoisoningDetector::new(),
        }
    }

    /// Get escape detector
    pub fn escape_detector(&mut self) -> &mut ContainerEscapeDetector {
        &mut self.escape_detector
    }

    /// Get K8s abuse detector
    pub fn k8s_abuse_detector(&mut self) -> &mut K8sApiAbuseDetector {
        &mut self.k8s_abuse_detector
    }

    /// Get lateral movement detector
    pub fn lateral_movement_detector(&mut self) -> &mut LateralMovementDetector {
        &mut self.lateral_movement_detector
    }

    /// Get registry poisoning detector
    pub fn registry_poisoning_detector(&mut self) -> &mut RegistryPoisoningDetector {
        &mut self.registry_poisoning_detector
    }

    /// Get comprehensive security report
    pub fn get_security_report(&self) -> ContainerSecurityReport {
        ContainerSecurityReport {
            escape_alerts: self.escape_detector.get_alerts().to_vec(),
            k8s_abuse_alerts: self.k8s_abuse_detector.get_alerts().to_vec(),
            lateral_movement_alerts: self.lateral_movement_detector.get_alerts().to_vec(),
            registry_poisoning_alerts: self.registry_poisoning_detector.get_alerts().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityReport {
    pub escape_alerts: Vec<ContainerEscapeAlert>,
    pub k8s_abuse_alerts: Vec<K8sApiAbuseAlert>,
    pub lateral_movement_alerts: Vec<LateralMovementAlert>,
    pub registry_poisoning_alerts: Vec<RegistryPoisoningAlert>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_escape_detection() {
        let mut detector = ContainerEscapeDetector::new();

        let info = ContainerInfo {
            container_id: "abc123".to_string(),
            container_name: "malicious".to_string(),
            privileged: true,
            host_mounts: vec!["/proc".to_string()],
            capabilities: vec!["CAP_SYS_ADMIN".to_string()],
            pid_namespace: "host".to_string(),
            network_namespace: "host".to_string(),
        };

        detector.register_container(info);
        let alerts = detector.check_escape_attempts("abc123");

        assert!(!alerts.is_empty());
        assert!(alerts
            .iter()
            .any(|a| matches!(a.escape_technique, EscapeTechnique::PrivilegedContainer)));
    }

    #[test]
    fn test_k8s_api_abuse_detection() {
        let mut detector = K8sApiAbuseDetector::new(3);

        for i in 0..5 {
            detector.record_api_call(
                "attacker".to_string(),
                K8sApiCall {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    verb: "GET".to_string(),
                    resource: "secrets".to_string(),
                    namespace: "default".to_string(),
                    name: Some(format!("secret{}", i)),
                    response_code: 200,
                },
            );
        }

        let alerts = detector.analyze_abuse("attacker");
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_lateral_movement_detection() {
        let mut detector = LateralMovementDetector::new();

        let alert = detector.detect_lateral_movement("pod1", "namespace1", "namespace2");

        assert!(alert.is_some());
    }

    #[test]
    fn test_registry_poisoning_detection() {
        let mut detector = RegistryPoisoningDetector::new();

        detector.register_trusted_image(
            "docker.io:nginx:latest".to_string(),
            "sha256:abc123".to_string(),
        );

        let alert = detector.verify_image("docker.io", "nginx", "latest", "sha256:malicious");

        assert!(alert.is_some());
    }
}
