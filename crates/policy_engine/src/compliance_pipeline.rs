// Multi-stage compliance pipeline with consensus and proof validation
// Orchestrates policy evaluation, consensus, proofs, and evidence emission
//
// ⚠️  EXPERIMENTAL: This pipeline uses stubbed CUE configuration.
// Stage execution returns simulated results until real integration is complete.

use crate::consensus::{ConsensusEngine, ConsensusResult, ConsensusVote};
use crate::cue_integration::{ComplianceStage, CueComplianceConfig};
use crate::proof_validator::ProofValidator;
use serde::{Deserialize, Serialize};

/// Result of a single pipeline stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage_name: String,
    pub success: bool,
    pub decision: String,
    pub proof: Option<String>,
    pub consensus: Option<ConsensusResult>,
    pub error: Option<String>,
}

/// Complete pipeline execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    pub policy_name: String,
    pub tenant_id: String,
    pub stages: Vec<StageResult>,
    pub final_decision: String,
    pub all_stages_passed: bool,
    pub consensus_hash: Option<String>,
    pub proof_aggregate: Option<String>,
    pub timestamp: u64,
}

/// Compliance pipeline orchestrator
pub struct CompliancePipeline {
    config: CueComplianceConfig,
    consensus_engine: Option<ConsensusEngine>,
    proof_validator: ProofValidator,
}

impl CompliancePipeline {
    /// Create a new compliance pipeline from CUE configuration
    pub fn new(config: CueComplianceConfig, validator_id: String) -> Self {
        // Build consensus engine if configured
        let consensus_engine = config.consensus_requirements.as_ref().map(|cr| {
            ConsensusEngine::with_weights(
                cr.threshold,
                cr.min_validators,
                cr.weight_threshold,
                cr.weights.clone(),
            )
        });

        let proof_validator = ProofValidator::new(validator_id);

        Self {
            config,
            consensus_engine,
            proof_validator,
        }
    }

    /// Execute the full compliance pipeline
    pub fn execute(
        &self,
        policy_name: &str,
        tenant_id: &str,
        policy_hash: &str,
        context: &serde_json::Value,
    ) -> PipelineResult {
        let mut stage_results = Vec::new();
        let mut final_decision = "deny".to_string();
        let mut all_passed = true;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Execute each stage in order
        for stage in &self.config.stages {
            let result = self.execute_stage(stage, policy_hash, context, tenant_id);

            if !result.success {
                all_passed = false;
                // Early exit on failure (fail-fast)
                stage_results.push(result);
                break;
            }

            final_decision = result.decision.clone();
            stage_results.push(result);
        }

        // Aggregate consensus hash if available
        let consensus_hash = stage_results
            .iter()
            .find_map(|r| r.consensus.as_ref().map(|c| c.consensus_hash.clone()));

        // Aggregate proofs
        let proof_aggregate = self.aggregate_stage_proofs(&stage_results);

        PipelineResult {
            policy_name: policy_name.to_string(),
            tenant_id: tenant_id.to_string(),
            stages: stage_results,
            final_decision: if all_passed {
                final_decision
            } else {
                "deny".to_string()
            },
            all_stages_passed: all_passed,
            consensus_hash,
            proof_aggregate,
            timestamp,
        }
    }

    /// Execute a single pipeline stage
    fn execute_stage(
        &self,
        stage: &ComplianceStage,
        policy_hash: &str,
        context: &serde_json::Value,
        tenant_id: &str,
    ) -> StageResult {
        match stage {
            ComplianceStage::PolicyEvaluation { .. } => {
                // Stub: would call PolicyEngine here
                StageResult {
                    stage_name: "policy_evaluation".to_string(),
                    success: true,
                    decision: "allow".to_string(),
                    proof: None,
                    consensus: None,
                    error: None,
                }
            }

            ComplianceStage::ProofValidation {
                proof_type,
                required,
            } => {
                let proof = self
                    .proof_validator
                    .generate_proof(policy_hash, "allow", context);

                let valid = self.proof_validator.verify_proof(&proof, policy_hash);

                StageResult {
                    stage_name: format!("proof_validation_{proof_type}"),
                    success: valid || !required,
                    decision: if valid { "allow" } else { "deny" }.to_string(),
                    proof: Some(proof.proof_data),
                    consensus: None,
                    error: if !valid && *required {
                        Some("Proof validation failed".to_string())
                    } else {
                        None
                    },
                }
            }

            ComplianceStage::Consensus {
                min_validators,
                threshold: _,
            } => {
                // Stub: would collect votes from validators
                // For now, simulate consensus with mock votes
                let votes = self.simulate_consensus_votes(tenant_id, *min_validators);

                if let Some(ref engine) = self.consensus_engine {
                    let result = engine.evaluate_with_domain(
                        &votes,
                        Some(tenant_id),
                        self.config
                            .consensus_requirements
                            .as_ref()
                            .and_then(|cr| cr.max_vote_age_secs),
                    );

                    StageResult {
                        stage_name: "consensus".to_string(),
                        success: result.threshold_met && result.quorum_reached,
                        decision: result.decision.clone(),
                        proof: result.proof_aggregate.clone(),
                        consensus: Some(result.clone()),
                        error: if !result.threshold_met {
                            Some("Consensus threshold not met".to_string())
                        } else if !result.quorum_reached {
                            Some("Quorum not reached".to_string())
                        } else {
                            None
                        },
                    }
                } else {
                    StageResult {
                        stage_name: "consensus".to_string(),
                        success: false,
                        decision: "deny".to_string(),
                        proof: None,
                        consensus: None,
                        error: Some("Consensus engine not configured".to_string()),
                    }
                }
            }

            ComplianceStage::ControlEvaluation {
                framework,
                controls: _,
            } => {
                // Stub: would call ComplianceEngine here
                StageResult {
                    stage_name: format!("control_evaluation_{framework}"),
                    success: true,
                    decision: "allow".to_string(),
                    proof: None,
                    consensus: None,
                    error: None,
                }
            }

            ComplianceStage::EvidenceEmission { index } => {
                // Stub: would write to compliance_index here
                StageResult {
                    stage_name: format!("evidence_emission_{index}"),
                    success: true,
                    decision: "allow".to_string(),
                    proof: None,
                    consensus: None,
                    error: None,
                }
            }
        }
    }

    /// Simulate consensus votes (stub for testing)
    fn simulate_consensus_votes(&self, tenant_id: &str, count: u32) -> Vec<ConsensusVote> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        (0..count)
            .map(|i| ConsensusVote {
                validator_id: format!("did:ritma:validator:node{}", i + 1),
                decision: "allow".to_string(),
                timestamp: now,
                proof: Some(format!("proof_{i}")),
                signature: format!("sig_{i}"),
                domain: Some(tenant_id.to_string()),
            })
            .collect()
    }

    /// Aggregate proofs from all stages
    fn aggregate_stage_proofs(&self, stages: &[StageResult]) -> Option<String> {
        use sha2::{Digest, Sha256};

        let proofs: Vec<String> = stages.iter().filter_map(|s| s.proof.clone()).collect();

        if proofs.is_empty() {
            return None;
        }

        let mut hasher = Sha256::new();
        for proof in &proofs {
            hasher.update(proof.as_bytes());
        }

        Some(hex::encode(hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cue_integration::ProofRequirements;

    #[test]
    fn pipeline_executes_all_stages() {
        let config = CueComplianceConfig {
            stages: vec![
                ComplianceStage::PolicyEvaluation {
                    policy_name: "test_policy".to_string(),
                    policy_version: "1.0.0".to_string(),
                },
                ComplianceStage::ProofValidation {
                    proof_type: "hash".to_string(),
                    required: true,
                },
            ],
            frameworks: vec!["SOC2".to_string()],
            proof_requirements: ProofRequirements {
                proof_type: "hash".to_string(),
                required: true,
                min_proofs: Some(1),
                aggregation: None,
            },
            consensus_requirements: None,
        };

        let pipeline = CompliancePipeline::new(config, "validator1".to_string());
        let result = pipeline.execute(
            "test_policy",
            "tenant_a",
            "policy_hash_123",
            &serde_json::json!({}),
        );

        assert_eq!(result.stages.len(), 2);
        assert!(result.all_stages_passed);
    }

    #[test]
    fn pipeline_fails_fast_on_stage_failure() {
        let config = CueComplianceConfig {
            stages: vec![
                ComplianceStage::Consensus {
                    min_validators: 2,
                    threshold: 2,
                },
                ComplianceStage::PolicyEvaluation {
                    policy_name: "test".to_string(),
                    policy_version: "1.0.0".to_string(),
                },
            ],
            frameworks: vec![],
            proof_requirements: ProofRequirements {
                proof_type: "hash".to_string(),
                required: true,
                min_proofs: None,
                aggregation: None,
            },
            consensus_requirements: None, // No consensus engine configured
        };

        let pipeline = CompliancePipeline::new(config, "validator1".to_string());
        let result = pipeline.execute(
            "test_policy",
            "tenant_a",
            "policy_hash",
            &serde_json::json!({}),
        );

        // Should stop after first stage failure (consensus without engine)
        assert_eq!(result.stages.len(), 1);
        assert!(!result.all_stages_passed);
        assert_eq!(result.final_decision, "deny");
    }
}
