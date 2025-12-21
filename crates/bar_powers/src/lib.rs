use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BarPowerError {
    #[error("config error: {0}")]
    Config(String),
    #[error("env error: {0}")]
    Env(String),
    #[error("pipeline error: {0}")]
    Pipeline(String),
    #[error("routes error: {0}")]
    Routes(String),
    #[error("boundary error: {0}")]
    Boundary(String),
    #[error("range error: {0}")]
    Range(String),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, BarPowerError>;

/// Adapter kinds that MiddlewarePower can construct.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Http,
    Otel,
    Grpc,
    Sdk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub json: serde_json::Value,
}

/// Canonical DecisionEvent candidate shape for adapters; the full
/// DecisionEvent lives in common_models.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionEventCandidate {
    pub namespace_id: String,
    pub event_type: String,
    #[serde(default)]
    pub raw: serde_json::Value,
}

pub trait Adapter: Send + Sync {
    fn kind(&self) -> AdapterKind;
}

/// 1) Middleware Power
pub trait MiddlewarePower {
    fn create_adapter(&self, kind: AdapterKind, config: AdapterConfig) -> Result<Box<dyn Adapter>>;
}

/// 2) Config Power
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveConfig {
    pub config_hash: String,
    pub json: serde_json::Value,
}

pub trait ConfigPower {
    fn effective_config(&self) -> Result<EffectiveConfig>;
}

/// 3) Env Power
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvContext {
    pub service: String,
    pub version: String,
    pub build_hash: String,
    pub runtime: String,
    pub region: String,
    #[serde(default)]
    pub trust_flags: Vec<String>,
}

pub trait EnvPower {
    fn sense_env(&self) -> Result<EnvContext>;
}

/// 4) Pipeline Power
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineInput {
    pub candidate: DecisionEventCandidate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineOutput {
    #[serde(default)]
    pub decision_event: Option<serde_json::Value>,
    #[serde(default)]
    pub verdict: Option<serde_json::Value>,
}

pub trait PipelinePower {
    fn process(&self, input: PipelineInput) -> Result<PipelineOutput>;
}

/// 5) Routes Power
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteMatch {
    pub packs: Vec<String>,
    pub destinations: Vec<String>,
}

pub trait RoutesPower {
    fn match_route(&self, event_type: &str, namespace_id: &str) -> Result<RouteMatch>;
}

/// 6) Boundary Power
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBoundaryDecision {
    pub redacted_payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionBoundaryDecision {
    pub allowed_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBoundaryDecision {
    pub allowed_destinations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityBoundaryDecision {
    pub can_modify_config: bool,
    pub can_modify_contracts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeBoundaryDecision {
    pub namespaces: Vec<String>,
}

pub trait BoundaryPower {
    fn enforce_data_boundary(&self, event: &serde_json::Value) -> Result<DataBoundaryDecision>;
    fn enforce_action_boundary(&self, event: &serde_json::Value) -> Result<ActionBoundaryDecision>;
    fn enforce_network_boundary(&self, event: &serde_json::Value) -> Result<NetworkBoundaryDecision>;
    fn enforce_authority_boundary(&self, actor: &serde_json::Value) -> Result<AuthorityBoundaryDecision>;
    fn enforce_scope_boundary(&self, event: &serde_json::Value) -> Result<ScopeBoundaryDecision>;
}

/// 7) Range Power
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    #[serde(default)]
    pub time: Option<serde_json::Value>,
    #[serde(default)]
    pub env: Option<serde_json::Value>,
    #[serde(default)]
    pub jurisdiction: Option<serde_json::Value>,
    #[serde(default)]
    pub service: Option<serde_json::Value>,
    #[serde(default)]
    pub policy: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeValidity {
    pub is_valid: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

pub trait RangePower {
    fn validate_range(&self, range: &Range, context: &serde_json::Value) -> Result<RangeValidity>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopPowers;

    impl MiddlewarePower for NoopPowers {
        fn create_adapter(&self, _kind: AdapterKind, _config: AdapterConfig) -> Result<Box<dyn Adapter>> {
            Err(BarPowerError::Other("noop".into()))
        }
    }

    impl ConfigPower for NoopPowers {
        fn effective_config(&self) -> Result<EffectiveConfig> {
            Ok(EffectiveConfig { config_hash: "h".into(), json: serde_json::json!({}) })
        }
    }

    impl EnvPower for NoopPowers {
        fn sense_env(&self) -> Result<EnvContext> {
            Ok(EnvContext {
                service: "svc".into(),
                version: "v1".into(),
                build_hash: "b".into(),
                runtime: "test".into(),
                region: "x".into(),
                trust_flags: vec![],
            })
        }
    }

    impl PipelinePower for NoopPowers {
        fn process(&self, _input: PipelineInput) -> Result<PipelineOutput> {
            Ok(PipelineOutput { decision_event: None, verdict: None })
        }
    }

    impl RoutesPower for NoopPowers {
        fn match_route(&self, _event_type: &str, _namespace_id: &str) -> Result<RouteMatch> {
            Ok(RouteMatch { packs: vec![], destinations: vec![] })
        }
    }

    impl BoundaryPower for NoopPowers {
        fn enforce_data_boundary(&self, _event: &serde_json::Value) -> Result<DataBoundaryDecision> {
            Ok(DataBoundaryDecision { redacted_payload: serde_json::json!({}) })
        }
        fn enforce_action_boundary(&self, _event: &serde_json::Value) -> Result<ActionBoundaryDecision> {
            Ok(ActionBoundaryDecision { allowed_actions: vec![] })
        }
        fn enforce_network_boundary(&self, _event: &serde_json::Value) -> Result<NetworkBoundaryDecision> {
            Ok(NetworkBoundaryDecision { allowed_destinations: vec![] })
        }
        fn enforce_authority_boundary(&self, _actor: &serde_json::Value) -> Result<AuthorityBoundaryDecision> {
            Ok(AuthorityBoundaryDecision { can_modify_config: false, can_modify_contracts: false })
        }
        fn enforce_scope_boundary(&self, _event: &serde_json::Value) -> Result<ScopeBoundaryDecision> {
            Ok(ScopeBoundaryDecision { namespaces: vec![] })
        }
    }

    impl RangePower for NoopPowers {
        fn validate_range(&self, _range: &Range, _context: &serde_json::Value) -> Result<RangeValidity> {
            Ok(RangeValidity { is_valid: true, reason: None })
        }
    }

    #[test]
    fn bar_powers_traits_compile() {
        let p = NoopPowers;
        let _ = p.effective_config().unwrap();
        let _ = p.sense_env().unwrap();
    }
}
