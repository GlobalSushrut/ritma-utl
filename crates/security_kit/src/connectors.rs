use serde::{Serialize, Deserialize};
use crate::{Result, SecurityKitError};
use crate::containers::ParamBundle;
use crate::observability;

/// High-level connector kind (clouds, k8s, storage, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConnectorKind {
    Aws,
    Gcp,
    Azure,
    Kubernetes,
    Storage,
}

/// Minimal configuration shared by all connectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    pub name: String,
    pub kind: ConnectorKind,
}

/// Standard trait that all connectors implement.
pub trait Connector: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> &ConnectorKind;

    /// Apply configuration/validation but do not mutate real infra yet.
    fn dry_run(&self, params: &ParamBundle) -> Result<()>;
}

/// Simple no-op connector used as a placeholder until real cloud integration.
#[derive(Debug, Clone)]
pub struct NoopConnector {
    cfg: ConnectorConfig,
}

impl NoopConnector {
    pub fn new(cfg: ConnectorConfig) -> Self {
        Self { cfg }
    }
}

impl Connector for NoopConnector {
    fn name(&self) -> &str { &self.cfg.name }
    fn kind(&self) -> &ConnectorKind { &self.cfg.kind }

    fn dry_run(&self, _params: &ParamBundle) -> Result<()> {
        // Intentionally no-op; this is safe to call in any environment.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::{ParamBundle, GeneralParams, SecretParams};
    use std::collections::BTreeMap;

    fn empty_bundle() -> ParamBundle {
        ParamBundle {
            general: GeneralParams(BTreeMap::new()),
            secrets: SecretParams(BTreeMap::new()),
            snapshot: None,
        }
    }

    #[test]
    fn k8s_non_strict_requires_basic_fields() {
        let conn = KubernetesConnector::new("k8s-test");
        let mut bundle = empty_bundle();
        bundle.general.0.insert("cluster".into(), "c1".into());
        bundle.general.0.insert("region".into(), "us-east-1".into());
        bundle.secrets.0.insert("kube_token".into(), "t".into());

        assert!(conn.dry_run(&bundle).is_ok());
    }

    #[test]
    fn k8s_strict_fails_when_missing_namespace() {
        let conn = KubernetesConnector::new("k8s-strict");
        let mut bundle = empty_bundle();
        bundle.general.0.insert("cluster".into(), "c1".into());
        bundle.general.0.insert("region".into(), "us-east-1".into());
        bundle.general.0.insert("k8s_strict".into(), "true".into());
        bundle.secrets.0.insert("kube_token".into(), "t".into());

        let res = conn.dry_run(&bundle);
        assert!(res.is_err());
    }

    #[test]
    fn aws_requires_account_and_creds_or_role() {
        let conn = AwsConnector::new("aws-test");
        let mut bundle = empty_bundle();
        bundle.general.0.insert("aws_account_id".into(), "123456789012".into());
        bundle.general.0.insert("region".into(), "us-east-1".into());
        bundle.secrets.0.insert("aws_access_key_id".into(), "AKIA...".into());
        bundle.secrets.0.insert("aws_secret_access_key".into(), "secret".into());

        assert!(conn.dry_run(&bundle).is_ok());
    }
}

/// Kubernetes connector that validates configuration without mutating real infra.
#[derive(Debug, Clone)]
pub struct KubernetesConnector {
    cfg: ConnectorConfig,
}

impl KubernetesConnector {
    pub fn new(name: impl Into<String>) -> Self {
        let cfg = ConnectorConfig {
            name: name.into(),
            kind: ConnectorKind::Kubernetes,
        };
        Self { cfg }
    }
}

impl Connector for KubernetesConnector {
    fn name(&self) -> &str { &self.cfg.name }
    fn kind(&self) -> &ConnectorKind { &self.cfg.kind }

    fn dry_run(&self, params: &ParamBundle) -> Result<()> {
        let start = std::time::Instant::now();
        let general = &params.general.0;
        let secrets = &params.secrets.0;

        let tenant_id = general.get("tenant_id").map(|s| s.as_str());

        let mut missing = Vec::new();

        if !general.contains_key("cluster") {
            missing.push("general.cluster");
        }
        if !general.contains_key("region") {
            missing.push("general.region");
        }
        if !(secrets.contains_key("kubeconfig") || secrets.contains_key("kube_token")) {
            missing.push("secrets.kubeconfig_or_kube_token");
        }

        // Optional strict mode: require stronger security posture.
        let strict = general
            .get("k8s_strict")
            .map(|v| {
                let v = v.to_lowercase();
                v == "1" || v == "true" || v == "yes" || v == "strict"
            })
            .unwrap_or(false);

        if strict {
            if !general.contains_key("namespace") {
                missing.push("general.namespace");
            }

            // Expect explicit RBAC mode, e.g. "rbac".
            match general.get("rbac_mode") {
                Some(v) if v.to_lowercase() == "rbac" => {}
                _ => missing.push("general.rbac_mode=rbac"),
            }

            // Expect network policy to be enabled/enforced.
            match general.get("network_policy") {
                Some(v) => {
                    let v = v.to_lowercase();
                    if !(v == "enabled" || v == "enforced") {
                        missing.push("general.network_policy=enabled|enforced");
                    }
                }
                None => missing.push("general.network_policy"),
            }

            // Expect audit logging to be turned on.
            match general.get("audit_log_enabled") {
                Some(v) => {
                    let v = v.to_lowercase();
                    if !(v == "1" || v == "true" || v == "yes" || v == "enabled") {
                        missing.push("general.audit_log_enabled=true");
                    }
                }
                None => missing.push("general.audit_log_enabled"),
            }
        }

        if !missing.is_empty() {
            let msg = format!(
                "kubernetes connector '{}' missing required params: {}",
                self.cfg.name,
                missing.join(", ")
            );
            observability::emit_slo_event(
                "connector",
                "dry_run",
                tenant_id,
                Some(self.cfg.name.as_str()),
                "error",
                Some(start.elapsed().as_millis() as u64),
                Some(msg.as_str()),
            );
            return Err(SecurityKitError::ConnectorError(msg));
        }

        observability::emit_slo_event(
            "connector",
            "dry_run",
            tenant_id,
            Some(self.cfg.name.as_str()),
            "ok",
            Some(start.elapsed().as_millis() as u64),
            None,
        );

        Ok(())
    }
}

/// AWS connector that validates account configuration without mutating real infra.
#[derive(Debug, Clone)]
pub struct AwsConnector {
    cfg: ConnectorConfig,
}

impl AwsConnector {
    pub fn new(name: impl Into<String>) -> Self {
        let cfg = ConnectorConfig {
            name: name.into(),
            kind: ConnectorKind::Aws,
        };
        Self { cfg }
    }
}

impl Connector for AwsConnector {
    fn name(&self) -> &str { &self.cfg.name }
    fn kind(&self) -> &ConnectorKind { &self.cfg.kind }

    fn dry_run(&self, params: &ParamBundle) -> Result<()> {
        let start = std::time::Instant::now();
        let general = &params.general.0;
        let secrets = &params.secrets.0;

        let tenant_id = general.get("tenant_id").map(|s| s.as_str());

        let mut missing = Vec::new();

        if !general.contains_key("aws_account_id") {
            missing.push("general.aws_account_id");
        }
        if !general.contains_key("region") {
            missing.push("general.region");
        }

        let has_keys = secrets.contains_key("aws_access_key_id")
            && secrets.contains_key("aws_secret_access_key");
        let has_role = general.contains_key("role_arn");
        if !(has_keys || has_role) {
            missing.push("(aws_access_key_id+aws_secret_access_key) or general.role_arn");
        }

        // Optional strict mode for AWS.
        let strict = general
            .get("aws_strict")
            .map(|v| {
                let v = v.to_lowercase();
                v == "1" || v == "true" || v == "yes" || v == "strict"
            })
            .unwrap_or(false);

        if strict {
            // CloudTrail must be enabled.
            match general.get("cloudtrail_enabled") {
                Some(v) if matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "enabled") => {}
                _ => missing.push("general.cloudtrail_enabled=true"),
            }

            // AWS Config must be enabled.
            match general.get("config_enabled") {
                Some(v) if matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "enabled") => {}
                _ => missing.push("general.config_enabled=true"),
            }

            // GuardDuty must be enabled.
            match general.get("guardduty_enabled") {
                Some(v) if matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "enabled") => {}
                _ => missing.push("general.guardduty_enabled=true"),
            }
        }

        if !missing.is_empty() {
            let msg = format!(
                "aws connector '{}' missing required params: {}",
                self.cfg.name,
                missing.join(", ")
            );
            observability::emit_slo_event(
                "connector",
                "dry_run",
                tenant_id,
                Some(self.cfg.name.as_str()),
                "error",
                Some(start.elapsed().as_millis() as u64),
                Some(msg.as_str()),
            );
            return Err(SecurityKitError::ConnectorError(msg));
        }

        observability::emit_slo_event(
            "connector",
            "dry_run",
            tenant_id,
            Some(self.cfg.name.as_str()),
            "ok",
            Some(start.elapsed().as_millis() as u64),
            None,
        );

        Ok(())
    }
}

/// GCP connector that validates project configuration without mutating real infra.
#[derive(Debug, Clone)]
pub struct GcpConnector {
    cfg: ConnectorConfig,
}

impl GcpConnector {
    pub fn new(name: impl Into<String>) -> Self {
        let cfg = ConnectorConfig {
            name: name.into(),
            kind: ConnectorKind::Gcp,
        };
        Self { cfg }
    }
}

impl Connector for GcpConnector {
    fn name(&self) -> &str { &self.cfg.name }
    fn kind(&self) -> &ConnectorKind { &self.cfg.kind }

    fn dry_run(&self, params: &ParamBundle) -> Result<()> {
        let start = std::time::Instant::now();
        let general = &params.general.0;
        let secrets = &params.secrets.0;

        let tenant_id = general.get("tenant_id").map(|s| s.as_str());

        let mut missing = Vec::new();

        if !general.contains_key("gcp_project_id") {
            missing.push("general.gcp_project_id");
        }
        if !general.contains_key("region") {
            missing.push("general.region");
        }
        if !secrets.contains_key("gcp_service_account_key") {
            missing.push("secrets.gcp_service_account_key");
        }

        let strict = general
            .get("gcp_strict")
            .map(|v| {
                let v = v.to_lowercase();
                v == "1" || v == "true" || v == "yes" || v == "strict"
            })
            .unwrap_or(false);

        if strict {
            match general.get("audit_log_enabled") {
                Some(v) if matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "enabled") => {}
                _ => missing.push("general.audit_log_enabled=true"),
            }

            match general.get("org_policies_enforced") {
                Some(v) if matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "enforced") => {}
                _ => missing.push("general.org_policies_enforced=true"),
            }
        }

        if !missing.is_empty() {
            let msg = format!(
                "gcp connector '{}' missing required params: {}",
                self.cfg.name,
                missing.join(", ")
            );
            observability::emit_slo_event(
                "connector",
                "dry_run",
                tenant_id,
                Some(self.cfg.name.as_str()),
                "error",
                Some(start.elapsed().as_millis() as u64),
                Some(msg.as_str()),
            );
            return Err(SecurityKitError::ConnectorError(msg));
        }

        observability::emit_slo_event(
            "connector",
            "dry_run",
            tenant_id,
            Some(self.cfg.name.as_str()),
            "ok",
            Some(start.elapsed().as_millis() as u64),
            None,
        );

        Ok(())
    }
}

/// Storage connector for object storage (S3/GCS/Azure) configuration checks.
#[derive(Debug, Clone)]
pub struct StorageConnector {
    cfg: ConnectorConfig,
}

impl StorageConnector {
    pub fn new(name: impl Into<String>) -> Self {
        let cfg = ConnectorConfig {
            name: name.into(),
            kind: ConnectorKind::Storage,
        };
        Self { cfg }
    }
}

impl Connector for StorageConnector {
    fn name(&self) -> &str { &self.cfg.name }
    fn kind(&self) -> &ConnectorKind { &self.cfg.kind }

    fn dry_run(&self, params: &ParamBundle) -> Result<()> {
        let start = std::time::Instant::now();
        let general = &params.general.0;
        let secrets = &params.secrets.0;

        let mut missing = Vec::new();

        let kind = general.get("storage_kind").map(|s| s.to_lowercase());
        if kind.is_none() {
            missing.push("general.storage_kind (s3|gcs|azure_blob)");
        }
        if !general.contains_key("bucket") {
            missing.push("general.bucket");
        }

        if let Some(k) = &kind {
            match k.as_str() {
                "s3" => {
                    let has_keys = secrets.contains_key("aws_access_key_id")
                        && secrets.contains_key("aws_secret_access_key");
                    if !has_keys {
                        missing.push("secrets.aws_access_key_id+aws_secret_access_key");
                    }
                }
                "gcs" => {
                    if !secrets.contains_key("gcp_service_account_key") {
                        missing.push("secrets.gcp_service_account_key");
                    }
                }
                "azure_blob" => {
                    if !secrets.contains_key("azure_connection_string") {
                        missing.push("secrets.azure_connection_string");
                    }
                }
                _ => missing.push("general.storage_kind unsupported"),
            }
        }

        let strict = general
            .get("storage_strict")
            .map(|v| {
                let v = v.to_lowercase();
                v == "1" || v == "true" || v == "yes" || v == "strict"
            })
            .unwrap_or(false);

        if strict {
            match general.get("encryption_at_rest") {
                Some(v) if matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "enabled") => {}
                _ => missing.push("general.encryption_at_rest=true"),
            }

            match general.get("versioning_enabled") {
                Some(v) if matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "enabled") => {}
                _ => missing.push("general.versioning_enabled=true"),
            }

            match general.get("public_access_blocked") {
                Some(v) if matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "enabled") => {}
                _ => missing.push("general.public_access_blocked=true"),
            }
        }

        if !missing.is_empty() {
            let tenant_id = general.get("tenant_id").map(|s| s.as_str());
            let msg = format!(
                "storage connector '{}' missing required params: {}",
                self.cfg.name,
                missing.join(", ")
            );
            observability::emit_slo_event(
                "connector",
                "dry_run",
                tenant_id,
                Some(self.cfg.name.as_str()),
                "error",
                Some(start.elapsed().as_millis() as u64),
                Some(msg.as_str()),
            );
            return Err(SecurityKitError::ConnectorError(msg));
        }

        let tenant_id = general.get("tenant_id").map(|s| s.as_str());
        observability::emit_slo_event(
            "connector",
            "dry_run",
            tenant_id,
            Some(self.cfg.name.as_str()),
            "ok",
            Some(start.elapsed().as_millis() as u64),
            None,
        );

        Ok(())
    }
}
