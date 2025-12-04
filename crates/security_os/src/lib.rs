use serde::{Deserialize, Serialize};

/// Basic DID type for security identities in Ritma.
///
/// Examples:
/// - did:ritma:tenant:acme
/// - did:ritma:svc:acme:public_api
/// - did:ritma:zone:acme:internal
/// - did:ritma:id:acme:user-123
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(String);

impl Did {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        if !s.starts_with("did:ritma:") {
            return Err("DID must start with did:ritma:".to_string());
        }
        Ok(Did(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn kind(&self) -> DidKind {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() < 3 {
            return DidKind::Unknown;
        }
        match parts.get(2).copied() {
            Some("tenant") => DidKind::Tenant,
            Some("svc") => DidKind::Service,
            Some("zone") => DidKind::Zone,
            Some("id") => DidKind::Identity,
            _ => DidKind::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidKind {
    Tenant,
    Service,
    Zone,
    Identity,
    Unknown,
}

/// Scope of isolation for OS-level enforcement (cgroups, namespaces, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationScope {
    Service,  // did:ritma:svc:...
    Zone,     // did:ritma:zone:...
    Tenant,   // did:ritma:tenant:...
}

/// Simple isolation profile that a controller can apply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IsolationProfile {
    pub cpu_limit_pct: Option<u8>,   // 0-100
    pub memory_limit_mb: Option<u64>,
    pub network_egress: Option<bool>,
    pub network_ingress: Option<bool>,
}

/// High-level decision for a network or RPC flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDecision {
    Allow,
    Deny,
    Throttle { rate_per_sec: u32 },
    Isolate { ttl_secs: u64 },
}

/// Abstract controller that can apply cgroup-style isolation.
pub trait CgroupController {
    fn apply_profile(&self, scope: IsolationScope, did: &Did, profile: IsolationProfile)
        -> Result<(), String>;
}

/// Abstract controller that can enforce firewall-style decisions between DIDs.
pub trait FirewallController {
    fn enforce_flow(&self, src: &Did, dst: &Did, decision: FlowDecision)
        -> Result<(), String>;
}

