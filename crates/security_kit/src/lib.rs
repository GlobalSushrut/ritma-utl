pub mod compliance;
pub mod connectors;
pub mod containers;
pub mod env;
pub mod helpers;
pub mod observability;
pub mod pipelines;
pub mod rbac;
pub mod reporting;
pub mod truthscript_bridge;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityKitError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("connector error: {0}")]
    ConnectorError(String),
    #[error("pipeline error: {0}")]
    PipelineError(String),
    #[error("rbac error: {0}")]
    RbacError(String),
}

pub type Result<T> = std::result::Result<T, SecurityKitError>;

/// Top-level SDK facade: what application code will primarily interact with.
pub struct SecurityKit {
    pub env: env::EnvManager,
    pub rbac: rbac::RbacManager,
}

impl SecurityKit {
    pub fn builder() -> pipelines::SecurityKitBuilder {
        pipelines::SecurityKitBuilder::default()
    }
}
