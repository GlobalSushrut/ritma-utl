/// Developer-facing helper functions for common SecurityKit workflows.

use crate::{
    SecurityKit,
    containers::{ParamBundle, GeneralParams, SecretParams, SnapshotParams},
    env::EnvManager,
    rbac::RbacManager,
    reporting::SecurityReport,
    Result,
};
use std::collections::BTreeMap;

/// Quick-start builder for common dev/test scenarios.
pub struct QuickStart {
    tenant_id: String,
    env_vars: BTreeMap<String, String>,
    secrets: BTreeMap<String, String>,
}

impl QuickStart {
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            env_vars: BTreeMap::new(),
            secrets: BTreeMap::new(),
        }
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    pub fn secret(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.secrets.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Result<SecurityKit> {
        let mut env = EnvManager::new().with_tenant(&self.tenant_id);
        for (k, v) in self.env_vars {
            env.set_general(k, v);
        }
        for (k, v) in self.secrets {
            env.set_secret(k, v);
        }

        let rbac = RbacManager::new();

        SecurityKit::builder()
            .with_env(env)
            .with_rbac(rbac)
            .build()
    }
}

/// Generate a snapshot-style param bundle for deployment tracking.
pub fn deployment_bundle(
    deployer: impl Into<String>,
    git_sha: impl Into<String>,
    region: impl Into<String>,
) -> ParamBundle {
    let deployer = deployer.into();
    let git_sha = git_sha.into();
    let region = region.into();

    let mut general = BTreeMap::new();
    general.insert("region".to_string(), region);
    general.insert("deployment_type".to_string(), "automated".to_string());

    let snapshot = SnapshotParams {
        label: format!("deploy-{}", git_sha),
        ts: clock::TimeTick::now().raw_time,
        fields: vec![
            ("git_sha".to_string(), git_sha),
            ("deployer".to_string(), deployer),
        ].into_iter().collect(),
    };

    ParamBundle {
        general: GeneralParams(general),
        secrets: SecretParams(BTreeMap::new()),
        snapshot: Some(snapshot),
    }
}

/// Generate a quick compliance report for a tenant.
pub fn quick_compliance_report(tenant_id: &str) -> std::io::Result<SecurityReport> {
    SecurityReport::generate_for_tenant(Some(tenant_id))
}

/// Generate a global infra report (all tenants).
pub fn global_infra_report() -> std::io::Result<SecurityReport> {
    SecurityReport::generate_for_tenant(None)
}
