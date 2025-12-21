use std::collections::BTreeMap;
use crate::containers::ParamBundle;
use crate::connectors::{
    Connector, ConnectorConfig, ConnectorKind,
    NoopConnector, KubernetesConnector,
    AwsConnector, GcpConnector, StorageConnector,
};
use crate::env::EnvManager;
use crate::rbac::RbacManager;
use crate::{SecurityKit, Result};

/// Builder that assembles the top-level SecurityKit facade.
#[derive(Default)]
pub struct SecurityKitBuilder {
    pub env: EnvManager,
    pub rbac: RbacManager,
    pub connectors: BTreeMap<String, Box<dyn Connector>>,
}

impl SecurityKitBuilder {
    pub fn with_env(mut self, env: EnvManager) -> Self {
        self.env = env;
        self
    }

    pub fn with_rbac(mut self, rbac: RbacManager) -> Self {
        self.rbac = rbac;
        self
    }

    pub fn add_noop_connector(
        mut self,
        name: impl Into<String>,
        kind: ConnectorKind,
    ) -> Self {
        let cfg = ConnectorConfig { name: name.into(), kind };
        let c = NoopConnector::new(cfg);
        self.connectors.insert(c.name().to_string(), Box::new(c));
        self
    }

    /// Add a Kubernetes connector that validates cluster configuration.
    pub fn add_kubernetes_connector(
        mut self,
        name: impl Into<String>,
    ) -> Self {
        let c = KubernetesConnector::new(name);
        self.connectors.insert(c.name().to_string(), Box::new(c));
        self
    }

    /// Add an AWS connector for account validation.
    pub fn add_aws_connector(
        mut self,
        name: impl Into<String>,
    ) -> Self {
        let c = AwsConnector::new(name);
        self.connectors.insert(c.name().to_string(), Box::new(c));
        self
    }

    /// Add a GCP connector for project validation.
    pub fn add_gcp_connector(
        mut self,
        name: impl Into<String>,
    ) -> Self {
        let c = GcpConnector::new(name);
        self.connectors.insert(c.name().to_string(), Box::new(c));
        self
    }

    /// Add a storage connector for bucket validation.
    pub fn add_storage_connector(
        mut self,
        name: impl Into<String>,
    ) -> Self {
        let c = StorageConnector::new(name);
        self.connectors.insert(c.name().to_string(), Box::new(c));
        self
    }

    pub fn build(self) -> Result<SecurityKit> {
        Ok(SecurityKit {
            env: self.env,
            rbac: self.rbac,
        })
    }

    /// Dry-run all registered connectors with the provided params.
    pub fn dry_run_connectors(&self, params: &ParamBundle) -> Result<()> {
        for c in self.connectors.values() {
            c.dry_run(params)?;
        }
        Ok(())
    }
}
