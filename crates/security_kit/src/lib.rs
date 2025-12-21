pub mod containers;
pub mod connectors;
pub mod pipelines;
pub mod rbac;
pub mod env;
pub mod reporting;
pub mod truthscript_bridge;
pub mod helpers;
pub mod compliance;
pub mod observability;

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
