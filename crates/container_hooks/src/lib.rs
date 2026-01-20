//! OCI Container Runtime Hooks (Q1.2)
//!
//! Implements OCI runtime spec hooks for container lifecycle events:
//! - Prestart: Before container process starts
//! - CreateRuntime: After runtime creates container
//! - CreateContainer: After container created but before pivot_root
//! - StartContainer: Before user process starts
//! - Poststart: After user process starts
//! - Poststop: After container process exits

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HookError {
    #[error("hook execution failed: {0}")]
    ExecutionFailed(String),
    #[error("invalid OCI state: {0}")]
    InvalidState(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// OCI runtime state (passed to hooks via stdin)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciState {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub id: String,
    pub status: ContainerStatus,
    pub pid: Option<i32>,
    pub bundle: String,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerStatus {
    Creating,
    Created,
    Running,
    Stopped,
}

/// Hook type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HookType {
    Prestart,
    CreateRuntime,
    CreateContainer,
    StartContainer,
    Poststart,
    Poststop,
}

impl HookType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Prestart => "prestart",
            Self::CreateRuntime => "createRuntime",
            Self::CreateContainer => "createContainer",
            Self::StartContainer => "startContainer",
            Self::Poststart => "poststart",
            Self::Poststop => "poststop",
        }
    }
}

/// Hook configuration (OCI spec format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub path: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub timeout: Option<u32>,
}

/// Container lifecycle event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEvent {
    pub event_id: [u8; 32],
    pub timestamp: i64,
    pub hook_type: HookType,
    pub container_id: String,
    pub container_pid: Option<i32>,
    pub bundle_path: String,
    pub image_id: Option<String>,
    pub image_name: Option<String>,
    pub labels: HashMap<String, String>,
    pub namespace: Option<String>,
    pub pod_name: Option<String>,
    pub pod_uid: Option<String>,
}

impl ContainerEvent {
    pub fn from_oci_state(state: &OciState, hook_type: HookType) -> Self {
        let timestamp = chrono::Utc::now().timestamp();
        let event_id = Self::compute_event_id(timestamp, hook_type, &state.id);

        // Extract Kubernetes metadata from annotations
        let namespace = state
            .annotations
            .get("io.kubernetes.pod.namespace")
            .cloned();
        let pod_name = state.annotations.get("io.kubernetes.pod.name").cloned();
        let pod_uid = state.annotations.get("io.kubernetes.pod.uid").cloned();
        let image_name = state
            .annotations
            .get("io.kubernetes.container.image")
            .cloned();

        Self {
            event_id,
            timestamp,
            hook_type,
            container_id: state.id.clone(),
            container_pid: state.pid,
            bundle_path: state.bundle.clone(),
            image_id: None,
            image_name,
            labels: state.annotations.clone(),
            namespace,
            pod_name,
            pod_uid,
        }
    }

    fn compute_event_id(timestamp: i64, hook_type: HookType, container_id: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-container-event@0.1");
        h.update(timestamp.to_le_bytes());
        h.update([hook_type as u8]);
        h.update(container_id.as_bytes());
        h.finalize().into()
    }

    pub fn event_id_hex(&self) -> String {
        hex::encode(self.event_id)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Hook handler trait
pub trait HookHandler: Send + Sync {
    fn handle(&self, event: &ContainerEvent) -> Result<HookAction, HookError>;
}

/// Action to take after hook
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAction {
    /// Allow container to proceed
    Allow,
    /// Block container (return non-zero exit)
    Block,
    /// Log and allow
    LogAndAllow,
}

/// Security policy for container hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPolicy {
    pub policy_id: String,
    pub name: String,
    pub enabled: bool,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub description: String,
    pub condition: PolicyCondition,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyCondition {
    /// Match container image
    ImageMatch { patterns: Vec<String> },
    /// Match namespace
    NamespaceMatch { namespaces: Vec<String> },
    /// Match labels
    LabelMatch { labels: HashMap<String, String> },
    /// Match privileged containers
    Privileged,
    /// Match host network
    HostNetwork,
    /// Match host PID
    HostPid,
    /// Always match
    Always,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
    Audit,
    Alert,
}

impl ContainerPolicy {
    pub fn evaluate(&self, event: &ContainerEvent) -> PolicyAction {
        if !self.enabled {
            return PolicyAction::Allow;
        }

        for rule in &self.rules {
            if self.matches_condition(&rule.condition, event) {
                return rule.action;
            }
        }

        PolicyAction::Allow
    }

    fn matches_condition(&self, condition: &PolicyCondition, event: &ContainerEvent) -> bool {
        match condition {
            PolicyCondition::ImageMatch { patterns } => {
                if let Some(ref image) = event.image_name {
                    patterns.iter().any(|p| image.contains(p))
                } else {
                    false
                }
            }
            PolicyCondition::NamespaceMatch { namespaces } => {
                if let Some(ref ns) = event.namespace {
                    namespaces.contains(ns)
                } else {
                    false
                }
            }
            PolicyCondition::LabelMatch { labels } => {
                labels.iter().all(|(k, v)| event.labels.get(k) == Some(v))
            }
            PolicyCondition::Privileged => {
                event
                    .labels
                    .get("io.kubernetes.container.securityContext.privileged")
                    == Some(&"true".to_string())
            }
            PolicyCondition::HostNetwork => {
                event.labels.get("io.kubernetes.pod.hostNetwork") == Some(&"true".to_string())
            }
            PolicyCondition::HostPid => {
                event.labels.get("io.kubernetes.pod.hostPID") == Some(&"true".to_string())
            }
            PolicyCondition::Always => true,
        }
    }
}

/// Container hook manager
pub struct HookManager {
    event_log: Vec<ContainerEvent>,
    policies: Vec<ContainerPolicy>,
    handlers: Vec<Box<dyn HookHandler>>,
    output_dir: PathBuf,
}

impl HookManager {
    pub fn new(output_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(output_dir)?;

        Ok(Self {
            event_log: Vec::new(),
            policies: Vec::new(),
            handlers: Vec::new(),
            output_dir: output_dir.to_path_buf(),
        })
    }

    pub fn add_policy(&mut self, policy: ContainerPolicy) {
        self.policies.push(policy);
    }

    pub fn add_handler(&mut self, handler: Box<dyn HookHandler>) {
        self.handlers.push(handler);
    }

    /// Process OCI hook invocation
    pub fn process_hook(
        &mut self,
        hook_type: HookType,
        state: OciState,
    ) -> Result<HookAction, HookError> {
        let event = ContainerEvent::from_oci_state(&state, hook_type);

        // Evaluate policies
        let mut final_action = HookAction::Allow;
        for policy in &self.policies {
            match policy.evaluate(&event) {
                PolicyAction::Deny => {
                    final_action = HookAction::Block;
                    break;
                }
                PolicyAction::Audit | PolicyAction::Alert => {
                    final_action = HookAction::LogAndAllow;
                }
                PolicyAction::Allow => {}
            }
        }

        // Run handlers
        for handler in &self.handlers {
            match handler.handle(&event) {
                Ok(action) => {
                    if action == HookAction::Block {
                        final_action = HookAction::Block;
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Hook handler error: {e}");
                }
            }
        }

        // Log event
        self.event_log.push(event);

        Ok(final_action)
    }

    /// Read OCI state from stdin (for hook binary)
    pub fn read_oci_state_from_stdin() -> Result<OciState, HookError> {
        let stdin = std::io::stdin();
        let state: OciState = serde_json::from_reader(stdin)?;
        Ok(state)
    }

    /// Flush events to disk
    pub fn flush(&mut self) -> std::io::Result<PathBuf> {
        if self.event_log.is_empty() {
            return Ok(self.output_dir.clone());
        }

        let now = chrono::Utc::now();
        let filename = format!("container_events_{}.cbor", now.format("%Y%m%d_%H%M%S"));
        let path = self.output_dir.join(&filename);

        let mut buf = Vec::new();
        ciborium::into_writer(&self.event_log, &mut buf).map_err(std::io::Error::other)?;
        std::fs::write(&path, buf)?;

        self.event_log.clear();
        Ok(path)
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.event_log.len()
    }
}

/// Generate OCI hook configuration for Ritma
pub fn generate_hook_config(ritma_hook_path: &str) -> HashMap<String, Vec<HookConfig>> {
    let mut hooks = HashMap::new();

    let base_config = HookConfig {
        path: ritma_hook_path.to_string(),
        args: vec![ritma_hook_path.to_string()],
        env: vec![],
        timeout: Some(30),
    };

    // CreateRuntime hook
    hooks.insert(
        "createRuntime".to_string(),
        vec![HookConfig {
            args: vec![ritma_hook_path.to_string(), "createRuntime".to_string()],
            ..base_config.clone()
        }],
    );

    // Poststart hook
    hooks.insert(
        "poststart".to_string(),
        vec![HookConfig {
            args: vec![ritma_hook_path.to_string(), "poststart".to_string()],
            ..base_config.clone()
        }],
    );

    // Poststop hook
    hooks.insert(
        "poststop".to_string(),
        vec![HookConfig {
            args: vec![ritma_hook_path.to_string(), "poststop".to_string()],
            ..base_config.clone()
        }],
    );

    hooks
}

/// Default security policy
pub fn default_security_policy() -> ContainerPolicy {
    ContainerPolicy {
        policy_id: "default".to_string(),
        name: "Default Container Security Policy".to_string(),
        enabled: true,
        rules: vec![
            PolicyRule {
                rule_id: "deny-privileged".to_string(),
                description: "Deny privileged containers".to_string(),
                condition: PolicyCondition::Privileged,
                action: PolicyAction::Deny,
            },
            PolicyRule {
                rule_id: "audit-host-network".to_string(),
                description: "Audit containers with host network".to_string(),
                condition: PolicyCondition::HostNetwork,
                action: PolicyAction::Audit,
            },
            PolicyRule {
                rule_id: "audit-host-pid".to_string(),
                description: "Audit containers with host PID".to_string(),
                condition: PolicyCondition::HostPid,
                action: PolicyAction::Audit,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_state() -> OciState {
        let mut annotations = HashMap::new();
        annotations.insert(
            "io.kubernetes.pod.namespace".to_string(),
            "default".to_string(),
        );
        annotations.insert("io.kubernetes.pod.name".to_string(), "test-pod".to_string());
        annotations.insert(
            "io.kubernetes.container.image".to_string(),
            "nginx:latest".to_string(),
        );

        OciState {
            oci_version: "1.0.2".to_string(),
            id: "container-123".to_string(),
            status: ContainerStatus::Created,
            pid: Some(12345),
            bundle: "/var/run/containers/container-123".to_string(),
            annotations,
        }
    }

    #[test]
    fn test_container_event_from_oci_state() {
        let state = make_test_state();
        let event = ContainerEvent::from_oci_state(&state, HookType::Poststart);

        assert_eq!(event.container_id, "container-123");
        assert_eq!(event.container_pid, Some(12345));
        assert_eq!(event.namespace, Some("default".to_string()));
        assert_eq!(event.pod_name, Some("test-pod".to_string()));
        assert_eq!(event.image_name, Some("nginx:latest".to_string()));
    }

    #[test]
    fn test_policy_evaluation() {
        let policy = default_security_policy();

        let mut state = make_test_state();
        let event = ContainerEvent::from_oci_state(&state, HookType::CreateRuntime);

        // Normal container should be allowed
        assert!(matches!(policy.evaluate(&event), PolicyAction::Allow));

        // Privileged container should be denied
        state.annotations.insert(
            "io.kubernetes.container.securityContext.privileged".to_string(),
            "true".to_string(),
        );
        let event = ContainerEvent::from_oci_state(&state, HookType::CreateRuntime);
        assert!(matches!(policy.evaluate(&event), PolicyAction::Deny));
    }

    #[test]
    fn test_hook_manager() {
        let tmp = std::env::temp_dir().join("container_hooks_test");
        let mut manager = HookManager::new(&tmp).unwrap();

        manager.add_policy(default_security_policy());

        let state = make_test_state();
        let action = manager.process_hook(HookType::Poststart, state).unwrap();

        assert_eq!(action, HookAction::Allow);
        assert_eq!(manager.event_count(), 1);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_generate_hook_config() {
        let hooks = generate_hook_config("/usr/local/bin/ritma-hook");

        assert!(hooks.contains_key("createRuntime"));
        assert!(hooks.contains_key("poststart"));
        assert!(hooks.contains_key("poststop"));
    }
}
