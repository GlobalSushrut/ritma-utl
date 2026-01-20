//! Kubernetes Admission Controller Webhooks (Q1.3)
//!
//! Implements validating and mutating admission webhooks for:
//! - Pod security policy enforcement
//! - Container image validation
//! - Resource quota enforcement
//! - Label/annotation injection
//! - Audit logging of all admission decisions

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("admission denied: {0}")]
    Denied(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("policy error: {0}")]
    PolicyError(String),
}

/// Kubernetes AdmissionReview request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReview {
    pub api_version: String,
    pub kind: String,
    pub request: Option<AdmissionRequest>,
    pub response: Option<AdmissionResponse>,
}

/// Admission request from API server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    pub uid: String,
    pub kind: GroupVersionKind,
    pub resource: GroupVersionResource,
    pub sub_resource: Option<String>,
    pub request_kind: Option<GroupVersionKind>,
    pub request_resource: Option<GroupVersionResource>,
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub operation: Operation,
    pub user_info: UserInfo,
    pub object: Option<serde_json::Value>,
    pub old_object: Option<serde_json::Value>,
    pub dry_run: Option<bool>,
    pub options: Option<serde_json::Value>,
}

/// Admission response to API server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionResponse {
    pub uid: String,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_annotations: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupVersionResource {
    pub group: String,
    pub version: String,
    pub resource: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Operation {
    Create,
    Update,
    Delete,
    Connect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub username: String,
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub extra: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// JSON Patch operation for mutating webhooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPatch {
    pub op: PatchOp,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatchOp {
    Add,
    Remove,
    Replace,
    Move,
    Copy,
    Test,
}

/// Admission decision for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionDecision {
    pub decision_id: [u8; 32],
    pub timestamp: i64,
    pub request_uid: String,
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub kind: String,
    pub operation: Operation,
    pub user: String,
    pub allowed: bool,
    pub reason: Option<String>,
    pub policy_matches: Vec<String>,
    pub mutations_applied: Vec<String>,
}

impl AdmissionDecision {
    pub fn new(request: &AdmissionRequest, allowed: bool, reason: Option<String>) -> Self {
        let timestamp = chrono::Utc::now().timestamp();
        let decision_id = Self::compute_id(timestamp, &request.uid);

        Self {
            decision_id,
            timestamp,
            request_uid: request.uid.clone(),
            namespace: request.namespace.clone(),
            name: request.name.clone(),
            kind: request.kind.kind.clone(),
            operation: request.operation,
            user: request.user_info.username.clone(),
            allowed,
            reason,
            policy_matches: Vec::new(),
            mutations_applied: Vec::new(),
        }
    }

    fn compute_id(timestamp: i64, uid: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-admission@0.1");
        h.update(timestamp.to_le_bytes());
        h.update(uid.as_bytes());
        h.finalize().into()
    }

    pub fn decision_id_hex(&self) -> String {
        hex::encode(self.decision_id)
    }
}

/// Validation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationPolicy {
    pub policy_id: String,
    pub name: String,
    pub enabled: bool,
    pub rules: Vec<ValidationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    pub rule_id: String,
    pub description: String,
    pub match_resources: ResourceMatch,
    pub validations: Vec<Validation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMatch {
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default)]
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Validation {
    /// Require specific labels
    RequireLabels { labels: Vec<String> },
    /// Deny privileged containers
    DenyPrivileged,
    /// Deny host namespaces
    DenyHostNamespaces,
    /// Require resource limits
    RequireResourceLimits,
    /// Allowed image registries
    AllowedRegistries { registries: Vec<String> },
    /// Deny latest tag
    DenyLatestTag,
    /// Require read-only root filesystem
    RequireReadOnlyRoot,
    /// Deny privilege escalation
    DenyPrivilegeEscalation,
    /// Custom CEL expression
    CelExpression { expression: String },
}

/// Mutation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationPolicy {
    pub policy_id: String,
    pub name: String,
    pub enabled: bool,
    pub mutations: Vec<Mutation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Mutation {
    /// Add labels
    AddLabels { labels: HashMap<String, String> },
    /// Add annotations
    AddAnnotations {
        annotations: HashMap<String, String>,
    },
    /// Set default resource limits
    SetDefaultLimits { cpu: String, memory: String },
    /// Add sidecar container
    AddSidecar { container: serde_json::Value },
    /// Set security context
    SetSecurityContext { context: serde_json::Value },
}

/// Validating admission webhook
pub struct ValidatingWebhook {
    policies: Vec<ValidationPolicy>,
    decisions: Vec<AdmissionDecision>,
}

impl ValidatingWebhook {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            decisions: Vec::new(),
        }
    }

    pub fn add_policy(&mut self, policy: ValidationPolicy) {
        self.policies.push(policy);
    }

    /// Validate an admission request
    pub fn validate(&mut self, request: &AdmissionRequest) -> AdmissionResponse {
        let mut decision = AdmissionDecision::new(request, true, None);
        let mut denied_reasons = Vec::new();
        let mut warnings = Vec::new();

        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }

            for rule in &policy.rules {
                if !self.matches_resource(&rule.match_resources, request) {
                    continue;
                }

                decision.policy_matches.push(rule.rule_id.clone());

                for validation in &rule.validations {
                    if let Err(reason) = self.apply_validation(validation, request) {
                        denied_reasons.push(format!("{}: {}", rule.rule_id, reason));
                    }
                }
            }
        }

        let allowed = denied_reasons.is_empty();
        decision.allowed = allowed;
        decision.reason = if allowed {
            None
        } else {
            Some(denied_reasons.join("; "))
        };

        self.decisions.push(decision.clone());

        let mut audit_annotations = HashMap::new();
        audit_annotations.insert(
            "ritma.io/decision-id".to_string(),
            decision.decision_id_hex(),
        );
        audit_annotations.insert(
            "ritma.io/policies-evaluated".to_string(),
            decision.policy_matches.join(","),
        );

        AdmissionResponse {
            uid: request.uid.clone(),
            allowed,
            status: if allowed {
                None
            } else {
                Some(Status {
                    code: 403,
                    message: denied_reasons.join("; "),
                    reason: Some("PolicyViolation".to_string()),
                })
            },
            patch: None,
            patch_type: None,
            audit_annotations: Some(audit_annotations),
            warnings: if warnings.is_empty() {
                None
            } else {
                Some(warnings)
            },
        }
    }

    fn matches_resource(&self, match_res: &ResourceMatch, request: &AdmissionRequest) -> bool {
        // Check kind
        if !match_res.kinds.is_empty() && !match_res.kinds.contains(&request.kind.kind) {
            return false;
        }

        // Check namespace
        if !match_res.namespaces.is_empty() {
            if let Some(ref ns) = request.namespace {
                if !match_res.namespaces.contains(ns) {
                    return false;
                }
            }
        }

        // Check operation
        if !match_res.operations.is_empty() && !match_res.operations.contains(&request.operation) {
            return false;
        }

        true
    }

    fn apply_validation(
        &self,
        validation: &Validation,
        request: &AdmissionRequest,
    ) -> Result<(), String> {
        let obj = request.object.as_ref().ok_or("no object in request")?;

        match validation {
            Validation::RequireLabels { labels } => {
                let obj_labels = obj.pointer("/metadata/labels").and_then(|v| v.as_object());

                for label in labels {
                    if obj_labels.map(|l| l.contains_key(label)).unwrap_or(false) {
                        continue;
                    }
                    return Err(format!("missing required label: {label}"));
                }
                Ok(())
            }

            Validation::DenyPrivileged => {
                if let Some(containers) = obj.pointer("/spec/containers") {
                    if let Some(arr) = containers.as_array() {
                        for container in arr {
                            let privileged = container
                                .pointer("/securityContext/privileged")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            if privileged {
                                return Err("privileged containers are not allowed".to_string());
                            }
                        }
                    }
                }
                Ok(())
            }

            Validation::DenyHostNamespaces => {
                let host_network = obj
                    .pointer("/spec/hostNetwork")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let host_pid = obj
                    .pointer("/spec/hostPID")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let host_ipc = obj
                    .pointer("/spec/hostIPC")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if host_network || host_pid || host_ipc {
                    return Err("host namespaces are not allowed".to_string());
                }
                Ok(())
            }

            Validation::RequireResourceLimits => {
                if let Some(containers) = obj.pointer("/spec/containers") {
                    if let Some(arr) = containers.as_array() {
                        for (i, container) in arr.iter().enumerate() {
                            let has_limits = container.pointer("/resources/limits").is_some();
                            if !has_limits {
                                return Err(format!("container {} missing resource limits", i));
                            }
                        }
                    }
                }
                Ok(())
            }

            Validation::AllowedRegistries { registries } => {
                if let Some(containers) = obj.pointer("/spec/containers") {
                    if let Some(arr) = containers.as_array() {
                        for container in arr {
                            if let Some(image) = container.get("image").and_then(|v| v.as_str()) {
                                let allowed = registries.iter().any(|r| image.starts_with(r));
                                if !allowed {
                                    return Err(format!(
                                        "image {} not from allowed registry",
                                        image
                                    ));
                                }
                            }
                        }
                    }
                }
                Ok(())
            }

            Validation::DenyLatestTag => {
                if let Some(containers) = obj.pointer("/spec/containers") {
                    if let Some(arr) = containers.as_array() {
                        for container in arr {
                            if let Some(image) = container.get("image").and_then(|v| v.as_str()) {
                                if image.ends_with(":latest") || !image.contains(':') {
                                    return Err(format!(
                                        "image {} uses latest tag or no tag",
                                        image
                                    ));
                                }
                            }
                        }
                    }
                }
                Ok(())
            }

            Validation::RequireReadOnlyRoot => {
                if let Some(containers) = obj.pointer("/spec/containers") {
                    if let Some(arr) = containers.as_array() {
                        for (i, container) in arr.iter().enumerate() {
                            let read_only = container
                                .pointer("/securityContext/readOnlyRootFilesystem")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            if !read_only {
                                return Err(format!(
                                    "container {} must have readOnlyRootFilesystem",
                                    i
                                ));
                            }
                        }
                    }
                }
                Ok(())
            }

            Validation::DenyPrivilegeEscalation => {
                if let Some(containers) = obj.pointer("/spec/containers") {
                    if let Some(arr) = containers.as_array() {
                        for (i, container) in arr.iter().enumerate() {
                            let allow_escalation = container
                                .pointer("/securityContext/allowPrivilegeEscalation")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true);
                            if allow_escalation {
                                return Err(format!("container {} allows privilege escalation", i));
                            }
                        }
                    }
                }
                Ok(())
            }

            Validation::CelExpression { expression: _ } => {
                // CEL evaluation would require a CEL runtime
                // For now, just pass
                Ok(())
            }
        }
    }

    pub fn get_decisions(&self) -> &[AdmissionDecision] {
        &self.decisions
    }
}

impl Default for ValidatingWebhook {
    fn default() -> Self {
        Self::new()
    }
}

/// Mutating admission webhook
pub struct MutatingWebhook {
    policies: Vec<MutationPolicy>,
    decisions: Vec<AdmissionDecision>,
}

impl MutatingWebhook {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            decisions: Vec::new(),
        }
    }

    pub fn add_policy(&mut self, policy: MutationPolicy) {
        self.policies.push(policy);
    }

    /// Mutate an admission request
    pub fn mutate(&mut self, request: &AdmissionRequest) -> AdmissionResponse {
        let mut decision = AdmissionDecision::new(request, true, None);
        let mut patches: Vec<JsonPatch> = Vec::new();

        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }

            for mutation in &policy.mutations {
                if let Some(patch) = self.apply_mutation(mutation, request) {
                    decision.mutations_applied.push(format!("{:?}", mutation));
                    patches.extend(patch);
                }
            }
        }

        self.decisions.push(decision.clone());

        let patch_json = if patches.is_empty() {
            None
        } else {
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                serde_json::to_string(&patches).unwrap_or_default(),
            ))
        };

        let mut audit_annotations = HashMap::new();
        audit_annotations.insert(
            "ritma.io/decision-id".to_string(),
            decision.decision_id_hex(),
        );
        audit_annotations.insert(
            "ritma.io/mutations-applied".to_string(),
            decision.mutations_applied.len().to_string(),
        );

        AdmissionResponse {
            uid: request.uid.clone(),
            allowed: true,
            status: None,
            patch: patch_json,
            patch_type: if patches.is_empty() {
                None
            } else {
                Some("JSONPatch".to_string())
            },
            audit_annotations: Some(audit_annotations),
            warnings: None,
        }
    }

    fn apply_mutation(
        &self,
        mutation: &Mutation,
        _request: &AdmissionRequest,
    ) -> Option<Vec<JsonPatch>> {
        match mutation {
            Mutation::AddLabels { labels } => {
                let mut patches = Vec::new();
                for (key, value) in labels {
                    patches.push(JsonPatch {
                        op: PatchOp::Add,
                        path: format!("/metadata/labels/{}", key.replace('/', "~1")),
                        value: Some(serde_json::Value::String(value.clone())),
                        from: None,
                    });
                }
                Some(patches)
            }

            Mutation::AddAnnotations { annotations } => {
                let mut patches = Vec::new();
                for (key, value) in annotations {
                    patches.push(JsonPatch {
                        op: PatchOp::Add,
                        path: format!("/metadata/annotations/{}", key.replace('/', "~1")),
                        value: Some(serde_json::Value::String(value.clone())),
                        from: None,
                    });
                }
                Some(patches)
            }

            Mutation::SetDefaultLimits { cpu, memory } => {
                // This would need to iterate containers
                let limits = serde_json::json!({
                    "cpu": cpu,
                    "memory": memory
                });
                Some(vec![JsonPatch {
                    op: PatchOp::Add,
                    path: "/spec/containers/0/resources/limits".to_string(),
                    value: Some(limits),
                    from: None,
                }])
            }

            Mutation::AddSidecar { container } => Some(vec![JsonPatch {
                op: PatchOp::Add,
                path: "/spec/containers/-".to_string(),
                value: Some(container.clone()),
                from: None,
            }]),

            Mutation::SetSecurityContext { context } => Some(vec![JsonPatch {
                op: PatchOp::Add,
                path: "/spec/securityContext".to_string(),
                value: Some(context.clone()),
                from: None,
            }]),
        }
    }

    pub fn get_decisions(&self) -> &[AdmissionDecision] {
        &self.decisions
    }
}

impl Default for MutatingWebhook {
    fn default() -> Self {
        Self::new()
    }
}

/// Default pod security policy
pub fn default_pod_security_policy() -> ValidationPolicy {
    ValidationPolicy {
        policy_id: "pod-security-baseline".to_string(),
        name: "Pod Security Baseline".to_string(),
        enabled: true,
        rules: vec![
            ValidationRule {
                rule_id: "deny-privileged".to_string(),
                description: "Deny privileged containers".to_string(),
                match_resources: ResourceMatch {
                    kinds: vec!["Pod".to_string()],
                    namespaces: vec![],
                    operations: vec![Operation::Create, Operation::Update],
                },
                validations: vec![Validation::DenyPrivileged],
            },
            ValidationRule {
                rule_id: "deny-host-namespaces".to_string(),
                description: "Deny host namespaces".to_string(),
                match_resources: ResourceMatch {
                    kinds: vec!["Pod".to_string()],
                    namespaces: vec![],
                    operations: vec![Operation::Create, Operation::Update],
                },
                validations: vec![Validation::DenyHostNamespaces],
            },
            ValidationRule {
                rule_id: "deny-privilege-escalation".to_string(),
                description: "Deny privilege escalation".to_string(),
                match_resources: ResourceMatch {
                    kinds: vec!["Pod".to_string()],
                    namespaces: vec![],
                    operations: vec![Operation::Create, Operation::Update],
                },
                validations: vec![Validation::DenyPrivilegeEscalation],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_request() -> AdmissionRequest {
        AdmissionRequest {
            uid: "test-uid-123".to_string(),
            kind: GroupVersionKind {
                group: "".to_string(),
                version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            resource: GroupVersionResource {
                group: "".to_string(),
                version: "v1".to_string(),
                resource: "pods".to_string(),
            },
            sub_resource: None,
            request_kind: None,
            request_resource: None,
            name: Some("test-pod".to_string()),
            namespace: Some("default".to_string()),
            operation: Operation::Create,
            user_info: UserInfo {
                username: "test-user".to_string(),
                uid: Some("user-123".to_string()),
                groups: vec!["system:authenticated".to_string()],
                extra: HashMap::new(),
            },
            object: Some(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "test-pod",
                    "namespace": "default",
                    "labels": {
                        "app": "test"
                    }
                },
                "spec": {
                    "containers": [{
                        "name": "main",
                        "image": "nginx:1.21",
                        "securityContext": {
                            "privileged": false,
                            "allowPrivilegeEscalation": false
                        },
                        "resources": {
                            "limits": {
                                "cpu": "100m",
                                "memory": "128Mi"
                            }
                        }
                    }]
                }
            })),
            old_object: None,
            dry_run: Some(false),
            options: None,
        }
    }

    #[test]
    fn test_validating_webhook_allow() {
        let mut webhook = ValidatingWebhook::new();
        webhook.add_policy(default_pod_security_policy());

        let request = make_test_request();
        let response = webhook.validate(&request);

        assert!(response.allowed);
        assert!(response.status.is_none());
    }

    #[test]
    fn test_validating_webhook_deny_privileged() {
        let mut webhook = ValidatingWebhook::new();
        webhook.add_policy(default_pod_security_policy());

        let mut request = make_test_request();
        request.object = Some(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod"},
            "spec": {
                "containers": [{
                    "name": "main",
                    "image": "nginx:1.21",
                    "securityContext": {
                        "privileged": true
                    }
                }]
            }
        }));

        let response = webhook.validate(&request);

        assert!(!response.allowed);
        assert!(response.status.is_some());
        assert!(response.status.unwrap().message.contains("privileged"));
    }

    #[test]
    fn test_mutating_webhook() {
        let mut webhook = MutatingWebhook::new();

        let mut labels = HashMap::new();
        labels.insert("ritma.io/monitored".to_string(), "true".to_string());

        webhook.add_policy(MutationPolicy {
            policy_id: "add-labels".to_string(),
            name: "Add Ritma Labels".to_string(),
            enabled: true,
            mutations: vec![Mutation::AddLabels { labels }],
        });

        let request = make_test_request();
        let response = webhook.mutate(&request);

        assert!(response.allowed);
        assert!(response.patch.is_some());
        assert_eq!(response.patch_type, Some("JSONPatch".to_string()));
    }

    #[test]
    fn test_admission_decision() {
        let request = make_test_request();
        let decision = AdmissionDecision::new(&request, true, None);

        assert_eq!(decision.request_uid, "test-uid-123");
        assert_eq!(decision.namespace, Some("default".to_string()));
        assert!(decision.allowed);
        assert!(!decision.decision_id_hex().is_empty());
    }
}
