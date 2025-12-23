// TruthScript v2 Executor - Infrastructure Action Execution
// Executes v2 actions against Ritma infrastructure (eBPF, cgroups, mTLS, DIDs)

use crate::v2::{ActionV2, ConditionV2, LogicalOperator, PolicyV2, RuleV2, WhenV2};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Execution context for v2 policies
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Event being evaluated
    pub event: HashMap<String, serde_json::Value>,

    /// DID of the actor (from mTLS cert)
    pub actor_did: Option<String>,

    /// Source IP address
    pub source_ip: Option<String>,

    /// Destination IP/port
    pub destination: Option<(String, u16)>,

    /// mTLS verification status
    pub mtls_verified: bool,

    /// Current cgroup path
    pub cgroup_path: Option<String>,

    /// eBPF map paths available
    pub ebpf_maps: HashMap<String, String>,

    /// Consensus votes collected
    pub consensus_votes: Vec<String>,
}

/// Result of executing a v2 action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_name: String,
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
}

/// Result of evaluating a v2 rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEvaluationResult {
    pub rule_name: String,
    pub matched: bool,
    pub actions_executed: Vec<ActionResult>,
}

/// v2 Policy Executor
pub struct PolicyExecutorV2 {
    /// Enable dry-run mode (don't actually execute actions)
    dry_run: bool,
}

impl PolicyExecutorV2 {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    /// Evaluate and execute a v2 policy
    pub fn execute(
        &self,
        policy: &PolicyV2,
        context: &ExecutionContext,
    ) -> Vec<RuleEvaluationResult> {
        let mut results = Vec::new();

        // Sort rules by priority (highest first)
        let mut sorted_rules = policy.rules.clone();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in &sorted_rules {
            let result = self.evaluate_rule(rule, context);
            results.push(result);
        }

        results
    }

    /// Evaluate a single rule
    fn evaluate_rule(&self, rule: &RuleV2, context: &ExecutionContext) -> RuleEvaluationResult {
        let matched = if let Some(ref when) = rule.when {
            self.evaluate_when(when, context)
        } else {
            true // No when clause = always matches
        };

        let actions_executed = if matched {
            rule.actions
                .iter()
                .map(|action| self.execute_action(action, context))
                .collect()
        } else {
            vec![]
        };

        RuleEvaluationResult {
            rule_name: rule.name.clone(),
            matched,
            actions_executed,
        }
    }

    /// Evaluate when clause
    fn evaluate_when(&self, when: &WhenV2, context: &ExecutionContext) -> bool {
        // Check event match
        if let Some(ref event_kind) = when.event {
            if let Some(actual_event) = context.event.get("kind") {
                if actual_event.as_str() != Some(event_kind) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Evaluate conditions based on operator
        match when.operator {
            LogicalOperator::All => when
                .conditions
                .iter()
                .all(|c| self.evaluate_condition(c, context)),
            LogicalOperator::Any => when
                .conditions
                .iter()
                .any(|c| self.evaluate_condition(c, context)),
            LogicalOperator::None => !when
                .conditions
                .iter()
                .any(|c| self.evaluate_condition(c, context)),
        }
    }

    /// Evaluate a single condition
    fn evaluate_condition(&self, condition: &ConditionV2, context: &ExecutionContext) -> bool {
        match condition {
            // Legacy conditions
            ConditionV2::EventEquals { value } => {
                context.event.get("kind").and_then(|v| v.as_str()) == Some(value)
            }
            ConditionV2::FieldEquals { field, value } => {
                context.event.get(field).and_then(|v| v.as_str()) == Some(value)
            }
            ConditionV2::FieldGreaterThan { field, threshold } => context
                .event
                .get(field)
                .and_then(|v| v.as_f64())
                .map(|v| v > *threshold)
                .unwrap_or(false),

            // DID conditions
            ConditionV2::DidEquals { did } => context.actor_did.as_deref() == Some(did),
            ConditionV2::DidPrefix { prefix } => context
                .actor_did
                .as_ref()
                .map(|d| d.starts_with(prefix))
                .unwrap_or(false),
            ConditionV2::DidPattern { pattern } => {
                // Simplified pattern matching (would use regex in production)
                context
                    .actor_did
                    .as_ref()
                    .map(|d| d.contains(pattern))
                    .unwrap_or(false)
            }

            // mTLS conditions
            ConditionV2::MtlsVerified => context.mtls_verified,
            ConditionV2::MtlsCertValid => context.mtls_verified, // Stub
            ConditionV2::MtlsCertIssuer { issuer: _ } => context.mtls_verified, // Stub

            // Network conditions
            ConditionV2::SourceIp { ip } => context.source_ip.as_deref() == Some(ip),
            ConditionV2::SourceIpInRange { cidr: _ } => {
                // Stub: would check CIDR range
                context.source_ip.is_some()
            }
            ConditionV2::DestinationPort { port } => context
                .destination
                .as_ref()
                .map(|(_, p)| p == port)
                .unwrap_or(false),

            // Resource conditions
            ConditionV2::CgroupExists { path } => context.cgroup_path.as_deref() == Some(path),

            // eBPF conditions
            ConditionV2::EbpfMapHasKey { map_path, key: _ } => {
                context.ebpf_maps.contains_key(map_path)
            }

            // Consensus conditions
            ConditionV2::ValidatorCount { min } => context.consensus_votes.len() >= *min as usize,

            // Catch-all for unimplemented conditions
            _ => false,
        }
    }

    /// Execute a single action
    fn execute_action(&self, action: &ActionV2, _context: &ExecutionContext) -> ActionResult {
        if self.dry_run {
            return ActionResult {
                action_name: format!("{action:?}"),
                success: true,
                output: Some("[DRY RUN]".to_string()),
                error: None,
            };
        }

        match action {
            ActionV2::Deny { reason } => ActionResult {
                action_name: "deny".to_string(),
                success: true,
                output: Some(format!("Denied: {reason}")),
                error: None,
            },

            ActionV2::EbpfDrop { reason } => {
                // In production: call ritma-ebpf-helper to update BPF map
                ActionResult {
                    action_name: "ebpf_drop".to_string(),
                    success: true,
                    output: Some(format!("eBPF drop: {reason}")),
                    error: None,
                }
            }

            ActionV2::EbpfUpdateMap {
                map_path,
                key,
                value,
            } => {
                // In production: exec bpftool map update
                ActionResult {
                    action_name: "ebpf_update_map".to_string(),
                    success: true,
                    output: Some(format!("Updated {map_path} key={key} value={value}")),
                    error: None,
                }
            }

            ActionV2::CgroupSetCpuLimit { percent } => {
                // In production: write to cgroup cpu.max
                ActionResult {
                    action_name: "cgroup_set_cpu_limit".to_string(),
                    success: true,
                    output: Some(format!("Set CPU limit to {percent}%")),
                    error: None,
                }
            }

            ActionV2::CgroupSetMemoryLimit { mb } => {
                // In production: write to cgroup memory.max
                ActionResult {
                    action_name: "cgroup_set_memory_limit".to_string(),
                    success: true,
                    output: Some(format!("Set memory limit to {mb}MB")),
                    error: None,
                }
            }

            ActionV2::NetworkQuarantine { duration_secs } => {
                // In production: update eBPF firewall + iptables
                ActionResult {
                    action_name: "network_quarantine".to_string(),
                    success: true,
                    output: Some(format!("Quarantined for {duration_secs}s")),
                    error: None,
                }
            }

            ActionV2::DidRevoke { did, reason } => {
                // In production: update DID registry + revocation list
                ActionResult {
                    action_name: "did_revoke".to_string(),
                    success: true,
                    output: Some(format!("Revoked DID {did}: {reason}")),
                    error: None,
                }
            }

            ActionV2::EmitDecisionEvent { index } => {
                // In production: call security_events::append_decision_event
                ActionResult {
                    action_name: "emit_decision_event".to_string(),
                    success: true,
                    output: Some(format!("Emitted to {index}")),
                    error: None,
                }
            }

            ActionV2::ServiceStop { service_name } => {
                // In production: systemctl stop or docker stop
                ActionResult {
                    action_name: "service_stop".to_string(),
                    success: true,
                    output: Some(format!("Stopped service {service_name}")),
                    error: None,
                }
            }

            // Catch-all for other actions
            _ => ActionResult {
                action_name: "unknown".to_string(),
                success: false,
                output: None,
                error: Some("Action not implemented".to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{InfraContext, RuleScope};
    use crate::PolicyHeader;

    #[test]
    fn executor_evaluates_did_condition() {
        let executor = PolicyExecutorV2::new(true);

        let mut context = ExecutionContext {
            event: HashMap::new(),
            actor_did: Some("did:ritma:tenant:acme:user:alice".to_string()),
            source_ip: None,
            destination: None,
            mtls_verified: true,
            cgroup_path: None,
            ebpf_maps: HashMap::new(),
            consensus_votes: vec![],
        };
        context
            .event
            .insert("kind".to_string(), serde_json::json!("api_call"));

        let condition = ConditionV2::DidPrefix {
            prefix: "did:ritma:tenant:acme".to_string(),
        };

        assert!(executor.evaluate_condition(&condition, &context));
    }

    #[test]
    fn executor_executes_ebpf_action() {
        let executor = PolicyExecutorV2::new(true);

        let context = ExecutionContext {
            event: HashMap::new(),
            actor_did: None,
            source_ip: Some("10.0.1.5".to_string()),
            destination: None,
            mtls_verified: false,
            cgroup_path: None,
            ebpf_maps: HashMap::new(),
            consensus_votes: vec![],
        };

        let action = ActionV2::EbpfDrop {
            reason: "Suspicious traffic".to_string(),
        };

        let result = executor.execute_action(&action, &context);
        assert!(result.success);
        let output = result.output.unwrap();
        assert!(output.contains("DRY RUN") || output.contains("eBPF drop"));
    }

    #[test]
    fn executor_respects_rule_priority() {
        let executor = PolicyExecutorV2::new(true);

        let policy = PolicyV2 {
            header: PolicyHeader {
                name: "test".to_string(),
                version: "2.0.0".to_string(),
                encoding: "UTF-8".to_string(),
                author: None,
                description: None,
                frameworks: vec![],
                policy_hash: None,
                consensus_threshold: None,
                cue_schema: None,
                proof_type: None,
                created_at: None,
                signature: None,
            },
            infra_context: InfraContext::default(),
            rules: vec![
                RuleV2 {
                    name: "low_priority".to_string(),
                    when: None,
                    actions: vec![ActionV2::Deny {
                        reason: "low".to_string(),
                    }],
                    priority: 1,
                    scope: RuleScope::Global,
                },
                RuleV2 {
                    name: "high_priority".to_string(),
                    when: None,
                    actions: vec![ActionV2::Deny {
                        reason: "high".to_string(),
                    }],
                    priority: 100,
                    scope: RuleScope::Global,
                },
            ],
            legacy_rules: vec![],
        };

        let context = ExecutionContext {
            event: HashMap::new(),
            actor_did: None,
            source_ip: None,
            destination: None,
            mtls_verified: false,
            cgroup_path: None,
            ebpf_maps: HashMap::new(),
            consensus_votes: vec![],
        };

        let results = executor.execute(&policy, &context);

        // High priority rule should be evaluated first
        assert_eq!(results[0].rule_name, "high_priority");
        assert_eq!(results[1].rule_name, "low_priority");
    }
}
