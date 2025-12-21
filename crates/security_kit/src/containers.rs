use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// General-purpose parameter container (non-secret).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeneralParams(pub BTreeMap<String, String>);

/// Secret parameter container (API keys, passwords, tokens).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretParams(pub BTreeMap<String, String>);

/// Snapshot-style param container for time-bounded, human-readable context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotParams {
    pub label: String,
    pub ts: u64,
    pub fields: BTreeMap<String, String>,
}

/// Typed bundle of the three main param containers for pipelines.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParamBundle {
    pub general: GeneralParams,
    pub secrets: SecretParams,
    pub snapshot: Option<SnapshotParams>,
}
