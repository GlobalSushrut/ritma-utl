/// Compliance and evidence integration for SecurityKit.
///
/// This module wires SecurityKit into the existing compliance_index and
/// evidence_package infrastructure for enterprise-grade audit trails.
use serde::{Deserialize, Serialize};

use compliance_index::{append_records, ControlEvalRecord};
use evidence_package::{
    EvidencePackageManifest, PackageBuilder, PackageScope, PackageSigner, PackageVerifier,
    SigningKey,
};
use node_keystore::{KeystoreKey, NodeKeystore};
use security_events::{append_decision_event, DecisionEvent};

use crate::{observability, Result, SecurityKitError};

/// Compliance event generated from SecurityKit operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvent {
    pub tenant_id: Option<String>,
    pub root_id: Option<String>,
    pub entity_id: Option<String>,
    pub framework: String,
    pub control_id: String,
    pub passed: bool,
    pub policy_commit_id: Option<String>,
}

impl ComplianceEvent {
    /// Convert to ControlEvalRecord for appending to compliance index.
    pub fn to_eval_record(&self) -> ControlEvalRecord {
        let ts = clock::TimeTick::now().raw_time;
        ControlEvalRecord {
            control_id: self.control_id.clone(),
            framework: self.framework.clone(),
            commit_id: self.policy_commit_id.clone(),
            tenant_id: self.tenant_id.clone(),
            root_id: self.root_id.clone(),
            entity_id: self.entity_id.clone(),
            ts,
            passed: self.passed,
            schema_version: 0,
            rulepack_id: None,
            rulepack_version: None,
            rule_hash: None,
            prev_hash: None,
            record_hash: None,
            svc_control_id: None,
            svc_infra_id: None,
        }
    }
}

/// Decision event generated from SecurityKit policy evaluations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionEvent {
    pub tenant_id: Option<String>,
    pub root_id: String,
    pub entity_id: String,
    pub event_kind: String,
    pub policy_name: String,
    pub policy_version: String,
    pub policy_decision: String,
    pub policy_rules: Vec<String>,
    pub policy_actions: Vec<String>,
}

impl PolicyDecisionEvent {
    /// Convert to DecisionEvent for appending to decision events log.
    pub fn to_decision_event(&self) -> DecisionEvent {
        DecisionEvent {
            ts: 0, // Will be set by append_decision_event
            tenant_id: self.tenant_id.clone(),
            root_id: self.root_id.clone(),
            entity_id: self.entity_id.clone(),
            event_kind: self.event_kind.clone(),
            policy_name: Some(self.policy_name.clone()),
            policy_version: Some(self.policy_version.clone()),
            policy_commit_id: None,
            policy_decision: self.policy_decision.clone(),
            policy_rules: self.policy_rules.clone(),
            policy_actions: self.policy_actions.clone(),
            src_did: None,
            dst_did: None,
            actor_did: None,
            src_zone: None,
            dst_zone: None,
            snark_high_threat_merkle_status: None,
            schema_version: 0,
            prev_hash: None,
            record_hash: None,
            consensus_decision: None,
            consensus_threshold_met: None,
            consensus_quorum_reached: None,
            consensus_total_weight: None,
            consensus_hash: None,
            consensus_validator_count: None,
            svc_policy_id: None,
            svc_infra_id: None,
        }
    }
}

/// Compliance recorder that writes to immutable logs.
pub struct ComplianceRecorder;

impl ComplianceRecorder {
    /// Record a batch of compliance events.
    pub fn record_compliance_events(events: &[ComplianceEvent]) -> std::io::Result<()> {
        let start = std::time::Instant::now();
        let records: Vec<ControlEvalRecord> = events.iter().map(|e| e.to_eval_record()).collect();
        let tenant = events.first().and_then(|e| e.tenant_id.as_deref());

        let res = append_records(&records);

        let latency = Some(start.elapsed().as_millis() as u64);
        match &res {
            Ok(_) => observability::emit_slo_event(
                "compliance",
                "record_compliance_events",
                tenant,
                None,
                "ok",
                latency,
                None,
            ),
            Err(e) => observability::emit_slo_event(
                "compliance",
                "record_compliance_events",
                tenant,
                None,
                "error",
                latency,
                Some(&e.to_string()),
            ),
        }

        res
    }

    /// Record a policy decision event.
    pub fn record_decision(event: &PolicyDecisionEvent) -> std::io::Result<()> {
        let start = std::time::Instant::now();
        let dec = event.to_decision_event();
        let tenant = dec.tenant_id.as_deref();

        let res = append_decision_event(&dec);

        let latency = Some(start.elapsed().as_millis() as u64);
        match &res {
            Ok(_) => observability::emit_slo_event(
                "compliance",
                "record_decision",
                tenant,
                None,
                "ok",
                latency,
                None,
            ),
            Err(e) => observability::emit_slo_event(
                "compliance",
                "record_decision",
                tenant,
                None,
                "error",
                latency,
                Some(&e.to_string()),
            ),
        }

        res
    }
}

/// Evidence package builder for SecurityKit.
pub struct EvidenceBuilder {
    tenant_id: String,
    scope: PackageScope,
    framework: Option<String>,
}

impl EvidenceBuilder {
    pub fn new(tenant_id: impl Into<String>, scope: PackageScope) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            scope,
            framework: None,
        }
    }

    pub fn with_framework(mut self, framework: impl Into<String>) -> Self {
        self.framework = Some(framework.into());
        self
    }

    /// Build evidence package manifest.
    pub fn build(self) -> Result<EvidencePackageManifest> {
        let start = std::time::Instant::now();
        let dig_index_db =
            std::env::var("UTLD_DIG_INDEX_DB").unwrap_or_else(|_| "./dig_index.sqlite".to_string());
        let dig_storage =
            std::env::var("UTLD_DIG_STORAGE").unwrap_or_else(|_| "./digs".to_string());
        let burn_storage =
            std::env::var("UTLD_BURN_STORAGE").unwrap_or_else(|_| "./burns".to_string());

        // Apply optional framework override into scope where applicable.
        let mut scope = self.scope;
        if let Some(fw) = self.framework {
            scope = match scope {
                PackageScope::PolicyCommit { commit_id, .. } => PackageScope::PolicyCommit {
                    commit_id,
                    framework: Some(fw),
                },
                PackageScope::TimeRange {
                    time_start,
                    time_end,
                    ..
                } => PackageScope::TimeRange {
                    time_start,
                    time_end,
                    framework: Some(fw),
                },
                other => other,
            };
        }

        let builder = PackageBuilder::new(self.tenant_id.clone(), scope)
            .dig_index_db(dig_index_db)
            .dig_storage_root(dig_storage)
            .burn_storage_root(burn_storage);

        let res = builder
            .build()
            .map_err(|e| SecurityKitError::PipelineError(e.to_string()));

        let latency = Some(start.elapsed().as_millis() as u64);
        match &res {
            Ok(_) => observability::emit_slo_event(
                "evidence",
                "build_package",
                Some(self.tenant_id.as_str()),
                None,
                "ok",
                latency,
                None,
            ),
            Err(e) => observability::emit_slo_event(
                "evidence",
                "build_package",
                Some(self.tenant_id.as_str()),
                None,
                "error",
                latency,
                Some(&e.to_string()),
            ),
        }

        res
    }

    /// Build and sign evidence package.
    pub fn build_and_sign(self, signing_key: SigningKey) -> Result<EvidencePackageManifest> {
        let start = std::time::Instant::now();
        let tenant = self.tenant_id.clone();
        let mut manifest = self.build()?;

        let signer = PackageSigner::new(signing_key, "security_kit".to_string());
        let res = signer
            .sign(&mut manifest)
            .map_err(|e| SecurityKitError::PipelineError(e.to_string()));

        let latency = Some(start.elapsed().as_millis() as u64);
        match &res {
            Ok(_) => observability::emit_slo_event(
                "evidence",
                "build_and_sign_package",
                Some(tenant.as_str()),
                None,
                "ok",
                latency,
                None,
            ),
            Err(e) => observability::emit_slo_event(
                "evidence",
                "build_and_sign_package",
                Some(tenant.as_str()),
                None,
                "error",
                latency,
                Some(&e.to_string()),
            ),
        }

        res.map(|_| manifest)
    }

    /// Build and sign evidence package using the node keystore and the
    /// RITMA_KEY_ID environment variable. This is a convenience wrapper
    /// around `build_and_sign` for typical node deployments.
    pub fn build_and_sign_with_keystore_env(self) -> Result<EvidencePackageManifest> {
        let key_id = std::env::var("RITMA_KEY_ID").map_err(|e| {
            SecurityKitError::PipelineError(format!(
                "RITMA_KEY_ID not set for keystore-based signing: {e}",
            ))
        })?;

        self.build_and_sign_with_keystore_key_id(&key_id)
    }

    /// Build and sign evidence package using a specific key_id from the
    /// node keystore. The keystore is loaded from `RITMA_KEYSTORE_PATH`
    /// or `./node_keystore.json` by default.
    pub fn build_and_sign_with_keystore_key_id(
        self,
        key_id: &str,
    ) -> Result<EvidencePackageManifest> {
        let ks = NodeKeystore::from_env().map_err(|e| {
            SecurityKitError::PipelineError(format!(
                "failed to load node keystore for signing: {e}",
            ))
        })?;

        let keystore_key = ks.key_for_signing(key_id).map_err(|e| {
            SecurityKitError::PipelineError(format!(
                "failed to load signing key {key_id} from keystore: {e}",
            ))
        })?;

        let signing_key = match keystore_key {
            KeystoreKey::HmacSha256(bytes) => SigningKey::HmacSha256(bytes),
            KeystoreKey::Ed25519(sk) => SigningKey::Ed25519(sk),
        };

        self.build_and_sign(signing_key)
    }
}

/// Verify an evidence package manifest.
pub fn verify_evidence_package(manifest: &EvidencePackageManifest, skip_artifacts: bool) -> bool {
    let mut verifier = PackageVerifier::new();
    if skip_artifacts {
        verifier = verifier.skip_artifacts();
    }
    let result = verifier.verify(manifest);
    result.is_valid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_event_converts_to_eval_record() {
        let event = ComplianceEvent {
            tenant_id: Some("acme".to_string()),
            root_id: Some("root1".to_string()),
            entity_id: Some("entity1".to_string()),
            framework: "SOC2".to_string(),
            control_id: "AC-3".to_string(),
            passed: true,
            policy_commit_id: Some("abc123".to_string()),
        };

        let record = event.to_eval_record();
        assert_eq!(record.control_id, "AC-3");
        assert_eq!(record.framework, "SOC2");
        assert!(record.passed);
    }

    #[test]
    fn decision_event_converts() {
        let event = PolicyDecisionEvent {
            tenant_id: Some("acme".to_string()),
            root_id: "root1".to_string(),
            entity_id: "entity1".to_string(),
            event_kind: "api_call".to_string(),
            policy_name: "security_policy".to_string(),
            policy_version: "1.0.0".to_string(),
            policy_decision: "allow".to_string(),
            policy_rules: vec!["RULE1".to_string()],
            policy_actions: vec!["log".to_string()],
        };

        let dec = event.to_decision_event();
        assert_eq!(dec.policy_decision, "allow");
        assert_eq!(dec.policy_name, Some("security_policy".to_string()));
    }
}
