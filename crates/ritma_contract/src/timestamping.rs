//! RFC3161 Timestamping and Delegation Chain Records
//!
//! Capability #8: Non-repudiation with:
//! - RFC3161 timestamp token support
//! - Trusted timestamp authority integration
//! - Delegation chain records
//! - Authority verification

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ============================================================================
// RFC3161 Timestamp Token
// ============================================================================

/// RFC3161 Timestamp Token (simplified representation)
#[derive(Debug, Clone)]
pub struct TimestampToken {
    /// Token ID
    pub token_id: String,
    /// Version
    pub version: u32,
    /// Policy OID
    pub policy_oid: String,
    /// Message imprint (hash algorithm + hash)
    pub message_imprint: MessageImprint,
    /// Serial number
    pub serial_number: u64,
    /// Generation time (RFC3339)
    pub gen_time: String,
    /// Accuracy (optional)
    pub accuracy: Option<Accuracy>,
    /// Ordering flag
    pub ordering: bool,
    /// Nonce (if provided in request)
    pub nonce: Option<u64>,
    /// TSA name
    pub tsa_name: Option<String>,
    /// Extensions
    pub extensions: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct MessageImprint {
    /// Hash algorithm OID
    pub hash_algorithm: String,
    /// Hash value
    pub hash_value: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Accuracy {
    /// Seconds
    pub seconds: Option<u32>,
    /// Milliseconds
    pub millis: Option<u32>,
    /// Microseconds
    pub micros: Option<u32>,
}

impl TimestampToken {
    /// Create a new timestamp token
    pub fn new(data_hash: [u8; 32], tsa_name: &str) -> Self {
        let now = chrono::Utc::now();
        let serial = now.timestamp_nanos_opt().unwrap_or(0) as u64;

        let token_id = {
            let mut h = Sha256::new();
            h.update(b"tst-id@0.1");
            h.update(&data_hash);
            h.update(&serial.to_le_bytes());
            format!("tst-{}", hex::encode(&h.finalize()[..12]))
        };

        Self {
            token_id,
            version: 1,
            policy_oid: "1.2.3.4.1".to_string(), // Example policy OID
            message_imprint: MessageImprint {
                hash_algorithm: "2.16.840.1.101.3.4.2.1".to_string(), // SHA-256 OID
                hash_value: data_hash,
            },
            serial_number: serial,
            gen_time: now.to_rfc3339(),
            accuracy: Some(Accuracy {
                seconds: Some(1),
                millis: None,
                micros: None,
            }),
            ordering: false,
            nonce: None,
            tsa_name: Some(tsa_name.to_string()),
            extensions: BTreeMap::new(),
        }
    }

    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn with_policy(mut self, policy_oid: &str) -> Self {
        self.policy_oid = policy_oid.to_string();
        self
    }

    /// Verify the token matches the data
    pub fn verify(&self, data: &[u8]) -> bool {
        let mut h = Sha256::new();
        h.update(data);
        let hash: [u8; 32] = h.finalize().into();
        hash == self.message_imprint.hash_value
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "rfc3161-token@0.1",
            &self.token_id,
            self.version,
            &self.policy_oid,
            &self.message_imprint.hash_algorithm,
            hex::encode(self.message_imprint.hash_value),
            self.serial_number,
            &self.gen_time,
            self.ordering,
            self.nonce,
            &self.tsa_name,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Timestamp Authority
// ============================================================================

/// Timestamp Authority configuration
#[derive(Debug, Clone)]
pub struct TimestampAuthority {
    /// Authority name
    pub name: String,
    /// Authority URL (for remote TSA)
    pub url: Option<String>,
    /// Policy OID
    pub policy_oid: String,
    /// Public key hash (for verification)
    pub public_key_hash: Option<[u8; 32]>,
    /// Is local (software TSA) or remote
    pub is_local: bool,
    /// Trust level
    pub trust_level: TrustLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// Self-signed, local only
    Local,
    /// Organization-level TSA
    Organization,
    /// Publicly trusted TSA
    Public,
    /// Qualified TSA (eIDAS, etc.)
    Qualified,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Organization => "organization",
            Self::Public => "public",
            Self::Qualified => "qualified",
        }
    }
}

impl TimestampAuthority {
    /// Create a local (software) TSA
    pub fn local(name: &str) -> Self {
        Self {
            name: name.to_string(),
            url: None,
            policy_oid: "1.2.3.4.1".to_string(),
            public_key_hash: None,
            is_local: true,
            trust_level: TrustLevel::Local,
        }
    }

    /// Create a remote TSA
    pub fn remote(name: &str, url: &str, trust_level: TrustLevel) -> Self {
        Self {
            name: name.to_string(),
            url: Some(url.to_string()),
            policy_oid: "1.2.3.4.1".to_string(),
            public_key_hash: None,
            is_local: false,
            trust_level,
        }
    }

    /// Issue a timestamp token (local TSA only)
    pub fn issue_token(&self, data: &[u8]) -> TimestampToken {
        let mut h = Sha256::new();
        h.update(data);
        let hash: [u8; 32] = h.finalize().into();

        TimestampToken::new(hash, &self.name).with_policy(&self.policy_oid)
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "tsa@0.1",
            &self.name,
            &self.url,
            &self.policy_oid,
            self.public_key_hash.map(hex::encode),
            self.is_local,
            self.trust_level.as_str(),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Delegation Chain
// ============================================================================

/// Delegation record in a chain of authority
#[derive(Debug, Clone)]
pub struct DelegationRecord {
    /// Delegation ID
    pub delegation_id: String,
    /// Delegator (who grants authority)
    pub delegator: Principal,
    /// Delegate (who receives authority)
    pub delegate: Principal,
    /// Scope of delegation
    pub scope: DelegationScope,
    /// Valid from (RFC3339)
    pub valid_from: String,
    /// Valid until (RFC3339, optional)
    pub valid_until: Option<String>,
    /// Constraints
    pub constraints: Vec<DelegationConstraint>,
    /// Signature from delegator
    pub signature: Option<String>,
    /// Timestamp token
    pub timestamp: Option<TimestampToken>,
    /// Parent delegation ID (for chained delegations)
    pub parent_delegation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Principal {
    /// Principal type
    pub principal_type: PrincipalType,
    /// Identifier
    pub identifier: String,
    /// Display name
    pub name: Option<String>,
    /// Public key hash
    pub public_key_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalType {
    User,
    Service,
    Device,
    Organization,
    System,
}

impl PrincipalType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Service => "service",
            Self::Device => "device",
            Self::Organization => "organization",
            Self::System => "system",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DelegationScope {
    /// Actions allowed
    pub actions: Vec<String>,
    /// Resources (namespaces, paths, etc.)
    pub resources: Vec<String>,
    /// Can re-delegate
    pub can_delegate: bool,
    /// Maximum delegation depth
    pub max_depth: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DelegationConstraint {
    /// Constraint type
    pub constraint_type: ConstraintType,
    /// Constraint value
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintType {
    /// Time-based constraint
    TimeWindow,
    /// IP/network constraint
    Network,
    /// Geographic constraint
    Geographic,
    /// Rate limit
    RateLimit,
    /// Custom constraint
    Custom,
}

impl ConstraintType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TimeWindow => "time_window",
            Self::Network => "network",
            Self::Geographic => "geographic",
            Self::RateLimit => "rate_limit",
            Self::Custom => "custom",
        }
    }
}

impl DelegationRecord {
    pub fn new(delegator: Principal, delegate: Principal, scope: DelegationScope) -> Self {
        let now = chrono::Utc::now();
        let delegation_id = {
            let mut h = Sha256::new();
            h.update(b"delegation@0.1");
            h.update(delegator.identifier.as_bytes());
            h.update(delegate.identifier.as_bytes());
            h.update(now.to_rfc3339().as_bytes());
            format!("del-{}", hex::encode(&h.finalize()[..12]))
        };

        Self {
            delegation_id,
            delegator,
            delegate,
            scope,
            valid_from: now.to_rfc3339(),
            valid_until: None,
            constraints: Vec::new(),
            signature: None,
            timestamp: None,
            parent_delegation_id: None,
        }
    }

    pub fn with_validity(mut self, until: &str) -> Self {
        self.valid_until = Some(until.to_string());
        self
    }

    pub fn with_constraint(mut self, constraint: DelegationConstraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    pub fn with_parent(mut self, parent_id: &str) -> Self {
        self.parent_delegation_id = Some(parent_id.to_string());
        self
    }

    pub fn with_timestamp(mut self, token: TimestampToken) -> Self {
        self.timestamp = Some(token);
        self
    }

    /// Check if delegation is currently valid
    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now().to_rfc3339();

        if self.valid_from > now {
            return false;
        }

        if let Some(ref until) = self.valid_until {
            if until < &now {
                return false;
            }
        }

        true
    }

    /// Compute delegation hash
    pub fn delegation_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"delegation-hash@0.1");
        h.update(self.delegation_id.as_bytes());
        h.update(self.delegator.identifier.as_bytes());
        h.update(self.delegate.identifier.as_bytes());
        h.update(self.valid_from.as_bytes());
        h.finalize().into()
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let delegator = (
            self.delegator.principal_type.as_str(),
            &self.delegator.identifier,
            &self.delegator.name,
        );
        let delegate = (
            self.delegate.principal_type.as_str(),
            &self.delegate.identifier,
            &self.delegate.name,
        );
        let scope = (
            &self.scope.actions,
            &self.scope.resources,
            self.scope.can_delegate,
            self.scope.max_depth,
        );

        let tuple = (
            "delegation-record@0.1",
            &self.delegation_id,
            delegator,
            delegate,
            scope,
            &self.valid_from,
            &self.valid_until,
            &self.signature,
            &self.parent_delegation_id,
            hex::encode(self.delegation_hash()),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

impl Principal {
    pub fn user(identifier: &str, name: Option<&str>) -> Self {
        Self {
            principal_type: PrincipalType::User,
            identifier: identifier.to_string(),
            name: name.map(|s| s.to_string()),
            public_key_hash: None,
        }
    }

    pub fn service(identifier: &str, name: Option<&str>) -> Self {
        Self {
            principal_type: PrincipalType::Service,
            identifier: identifier.to_string(),
            name: name.map(|s| s.to_string()),
            public_key_hash: None,
        }
    }

    pub fn with_public_key(mut self, hash: [u8; 32]) -> Self {
        self.public_key_hash = Some(hash);
        self
    }
}

impl DelegationScope {
    pub fn new(actions: Vec<String>, resources: Vec<String>) -> Self {
        Self {
            actions,
            resources,
            can_delegate: false,
            max_depth: None,
        }
    }

    pub fn with_delegation(mut self, can_delegate: bool, max_depth: Option<u32>) -> Self {
        self.can_delegate = can_delegate;
        self.max_depth = max_depth;
        self
    }
}

// ============================================================================
// Delegation Chain
// ============================================================================

/// Complete delegation chain
#[derive(Debug, Clone)]
pub struct DelegationChain {
    /// Chain ID
    pub chain_id: String,
    /// Root delegation
    pub root: DelegationRecord,
    /// Child delegations
    pub delegations: Vec<DelegationRecord>,
}

impl DelegationChain {
    pub fn new(root: DelegationRecord) -> Self {
        let chain_id = {
            let mut h = Sha256::new();
            h.update(b"chain@0.1");
            h.update(root.delegation_id.as_bytes());
            format!("chain-{}", hex::encode(&h.finalize()[..8]))
        };

        Self {
            chain_id,
            root,
            delegations: Vec::new(),
        }
    }

    /// Add a delegation to the chain
    pub fn add_delegation(&mut self, delegation: DelegationRecord) -> bool {
        // Verify parent exists
        let parent_id = delegation.parent_delegation_id.as_ref();
        let parent_exists = parent_id.map_or(false, |pid| {
            pid == &self.root.delegation_id
                || self.delegations.iter().any(|d| &d.delegation_id == pid)
        });

        if !parent_exists && delegation.parent_delegation_id.is_some() {
            return false;
        }

        self.delegations.push(delegation);
        true
    }

    /// Verify the entire chain
    pub fn verify(&self) -> ChainVerification {
        let mut issues = Vec::new();

        // Check root is valid
        if !self.root.is_valid() {
            issues.push("Root delegation is not valid".to_string());
        }

        // Check each delegation
        for (i, del) in self.delegations.iter().enumerate() {
            if !del.is_valid() {
                issues.push(format!("Delegation {} is not valid", i));
            }

            // Check parent exists and allows re-delegation
            if let Some(ref parent_id) = del.parent_delegation_id {
                let parent = if parent_id == &self.root.delegation_id {
                    Some(&self.root)
                } else {
                    self.delegations
                        .iter()
                        .find(|d| &d.delegation_id == parent_id)
                };

                if let Some(p) = parent {
                    if !p.scope.can_delegate {
                        issues.push(format!("Parent {} does not allow re-delegation", parent_id));
                    }
                } else {
                    issues.push(format!("Parent {} not found", parent_id));
                }
            }
        }

        ChainVerification {
            valid: issues.is_empty(),
            issues,
            chain_length: self.delegations.len() + 1,
        }
    }

    /// Get delegation path to a principal
    pub fn path_to(&self, principal_id: &str) -> Vec<&DelegationRecord> {
        let mut path = Vec::new();

        // Find the delegation for this principal
        let target = self
            .delegations
            .iter()
            .find(|d| d.delegate.identifier == principal_id);

        if let Some(del) = target {
            path.push(del);

            // Walk up the chain
            let mut current_parent = del.parent_delegation_id.as_ref();
            while let Some(parent_id) = current_parent {
                if parent_id == &self.root.delegation_id {
                    path.push(&self.root);
                    break;
                }
                if let Some(parent) = self
                    .delegations
                    .iter()
                    .find(|d| &d.delegation_id == parent_id)
                {
                    path.push(parent);
                    current_parent = parent.parent_delegation_id.as_ref();
                } else {
                    break;
                }
            }
        }

        path.reverse();
        path
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let delegations: Vec<_> = self
            .delegations
            .iter()
            .map(|d| {
                (
                    &d.delegation_id,
                    &d.delegator.identifier,
                    &d.delegate.identifier,
                )
            })
            .collect();

        let tuple = (
            "delegation-chain@0.1",
            &self.chain_id,
            &self.root.delegation_id,
            &self.root.delegator.identifier,
            delegations.len(),
            delegations,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

#[derive(Debug, Clone)]
pub struct ChainVerification {
    pub valid: bool,
    pub issues: Vec<String>,
    pub chain_length: usize,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_token() {
        let data = b"test data to timestamp";
        let mut h = Sha256::new();
        h.update(data);
        let hash: [u8; 32] = h.finalize().into();

        let token = TimestampToken::new(hash, "Local TSA").with_nonce(12345);

        assert!(!token.token_id.is_empty());
        assert!(token.verify(data));
        assert!(!token.verify(b"wrong data"));

        let cbor = token.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_timestamp_authority() {
        let tsa = TimestampAuthority::local("Test TSA");
        assert!(tsa.is_local);
        assert_eq!(tsa.trust_level, TrustLevel::Local);

        let token = tsa.issue_token(b"test data");
        assert!(token.verify(b"test data"));

        let cbor = tsa.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_delegation_record() {
        let delegator = Principal::user("admin@example.com", Some("Admin"));
        let delegate = Principal::service("service-a", Some("Service A"));
        let scope = DelegationScope::new(
            vec!["read".to_string(), "write".to_string()],
            vec!["ns://prod/*".to_string()],
        )
        .with_delegation(true, Some(2));

        let delegation =
            DelegationRecord::new(delegator, delegate, scope).with_validity("2099-12-31T23:59:59Z");

        assert!(!delegation.delegation_id.is_empty());
        assert!(delegation.is_valid());
        assert_ne!(delegation.delegation_hash(), [0u8; 32]);

        let cbor = delegation.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_delegation_chain() {
        // Root: Org -> Admin
        let org = Principal::user("org@example.com", Some("Organization"));
        let admin = Principal::user("admin@example.com", Some("Admin"));
        let root_scope = DelegationScope::new(vec!["*".to_string()], vec!["*".to_string()])
            .with_delegation(true, Some(3));
        let root = DelegationRecord::new(org, admin.clone(), root_scope);
        let root_id = root.delegation_id.clone();

        let mut chain = DelegationChain::new(root);

        // Admin -> Service
        let service = Principal::service("service-a", Some("Service A"));
        let service_scope =
            DelegationScope::new(vec!["read".to_string()], vec!["ns://prod/*".to_string()])
                .with_delegation(false, None);
        let del1 = DelegationRecord::new(admin, service, service_scope).with_parent(&root_id);

        assert!(chain.add_delegation(del1));

        let verification = chain.verify();
        assert!(verification.valid, "Issues: {:?}", verification.issues);
        assert_eq!(verification.chain_length, 2);

        let cbor = chain.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_delegation_with_timestamp() {
        let tsa = TimestampAuthority::local("Test TSA");

        let delegator = Principal::user("admin", None);
        let delegate = Principal::service("svc", None);
        let scope = DelegationScope::new(vec!["read".to_string()], vec!["*".to_string()]);

        let delegation = DelegationRecord::new(delegator, delegate, scope);
        let token = tsa.issue_token(&delegation.to_cbor());
        let delegation = delegation.with_timestamp(token);

        assert!(delegation.timestamp.is_some());
    }
}
