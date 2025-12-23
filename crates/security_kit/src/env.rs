use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Declarative description of environment variables for a tenant/app.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvSpec {
    pub tenant_id: Option<String>,
    pub general: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, String>,
}

/// Simple env generator that can be serialized to .env or shell exports.
#[derive(Debug, Clone, Default)]
pub struct EnvManager {
    pub spec: EnvSpec,
}

impl EnvManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.spec.tenant_id = Some(tenant.into());
        self
    }

    pub fn set_general(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.spec.general.insert(key.into(), value.into());
    }

    pub fn set_secret(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.spec.secrets.insert(key.into(), value.into());
    }

    /// Render to simple KEY=VALUE lines (secrets included), for local dev only.
    pub fn to_env_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (k, v) in &self.spec.general {
            out.push(format!("{k}={v}"));
        }
        for (k, v) in &self.spec.secrets {
            out.push(format!("{k}={v}"));
        }
        out
    }
}
