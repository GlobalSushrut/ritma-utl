//! # Forensic ML - Military-Grade Explainable Inference Engine
//!
//! This crate implements a 4-layer forensic ML architecture for Ritma BAR:
//!
//! ## Layer A: Deterministic Feature Core (Non-ML)
//! - Process graph structure metrics
//! - Temporal causality chains
//! - Entropy / rarity scores
//! - Privilege transition patterns
//! - IO / syscall flow invariants
//!
//! ## Layer B: Statistical Anomaly Models (Classical ML)
//! - Isolation Forest
//! - Local Outlier Factor (LOF)
//! - Robust PCA
//! - HMM for sequences
//!
//! ## Layer C: Behavior Similarity Embeddings
//! - Graph embeddings
//! - Sequence embeddings
//! - All with versioned hashes
//!
//! ## Layer D: Verdict Synthesis Layer
//! - Rule-governed aggregation
//! - Versioned weights + formula
//!
//! ## Core Principles
//! - **Determinism**: Same input MUST produce same ML result
//! - **Explainability**: Every score must be explainable
//! - **Provability**: Model ID, version hash, feature hash logged
//! - **Auditability > Accuracy**: Reproducibility over raw detection rate

pub mod layer_a;
pub mod layer_b;
pub mod layer_c;
pub mod layer_d;
pub mod notary;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use layer_a::DeterministicFeatures;
pub use layer_b::StatisticalAnomalyResult;
pub use layer_c::BehaviorEmbedding;
pub use layer_d::VerdictSynthesis;
pub use notary::{MLNotarizedResult, MLNotary};

/// Forensic ML Engine version - MUST be bumped on any inference logic change
pub const ENGINE_VERSION: &str = "1.0.0";

/// Engine version hash for provenance
pub fn engine_version_hash() -> String {
    let mut h = Sha256::new();
    h.update(b"ritma-forensic-ml@");
    h.update(ENGINE_VERSION.as_bytes());
    hex::encode(h.finalize())
}

/// Fixed random seed for deterministic inference
pub const DETERMINISTIC_SEED: u64 = 0x52_49_54_4D_41_4D_4C_31; // "RITMAML1"

/// Forensic ML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct ForensicMLConfig {
    /// Layer weights for verdict synthesis
    pub weights: VerdictWeights,
    /// Anomaly thresholds
    pub thresholds: AnomalyThresholds,
    /// Model versions (frozen for inference)
    pub model_versions: ModelVersions,
    /// Explainability requirements
    pub explainability: ExplainabilityConfig,
}


/// Verdict synthesis weights (per spec: versioned and logged)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictWeights {
    /// Weight for deterministic evidence (Layer A)
    pub w1_deterministic: f64,
    /// Weight for anomaly score (Layer B)
    pub w2_anomaly: f64,
    /// Weight for similarity risk (Layer C)
    pub w3_similarity: f64,
    /// Weight for policy violation (Layer D rules)
    pub w4_policy: f64,
}

impl Default for VerdictWeights {
    fn default() -> Self {
        Self {
            w1_deterministic: 0.35,
            w2_anomaly: 0.30,
            w3_similarity: 0.15,
            w4_policy: 0.20,
        }
    }
}

impl VerdictWeights {
    pub fn version_hash(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(b"ritma-verdict-weights@0.1:");
        h.update(json.as_bytes());
        hex::encode(h.finalize())
    }
}

/// Anomaly detection thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyThresholds {
    /// Isolation Forest threshold
    pub isolation_forest: f64,
    /// LOF threshold
    pub lof: f64,
    /// Statistical baseline (std deviations)
    pub baseline_std: f64,
    /// Entropy threshold for rarity
    pub entropy: f64,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            isolation_forest: 0.6,
            lof: 1.5,
            baseline_std: 3.0,
            entropy: 0.7,
        }
    }
}

/// Model versions (frozen for reproducible inference)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVersions {
    pub isolation_forest: String,
    pub lof: String,
    pub hmm: String,
    pub graph_embedding: String,
    pub sequence_embedding: String,
}

impl Default for ModelVersions {
    fn default() -> Self {
        Self {
            isolation_forest: "if-v1.0.0".to_string(),
            lof: "lof-v1.0.0".to_string(),
            hmm: "hmm-v1.0.0".to_string(),
            graph_embedding: "ge-v1.0.0".to_string(),
            sequence_embedding: "se-v1.0.0".to_string(),
        }
    }
}

impl ModelVersions {
    pub fn combined_hash(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(b"ritma-model-versions@0.1:");
        h.update(json.as_bytes());
        hex::encode(h.finalize())
    }
}

/// Explainability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainabilityConfig {
    /// Require top-N feature contributions
    pub min_feature_contributions: usize,
    /// Require graph edge explanations
    pub require_graph_edges: bool,
    /// Require temporal sequence deviations
    pub require_temporal_deviations: bool,
    /// Require policy constraint explanations
    pub require_policy_constraints: bool,
}

impl Default for ExplainabilityConfig {
    fn default() -> Self {
        Self {
            min_feature_contributions: 5,
            require_graph_edges: true,
            require_temporal_deviations: true,
            require_policy_constraints: true,
        }
    }
}

/// Complete forensic ML result (all 4 layers + notarization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMLResult {
    /// Unique result ID
    pub result_id: String,
    /// Timestamp
    pub timestamp: String,
    /// Namespace
    pub namespace_id: String,
    /// Window ID
    pub window_id: String,

    /// Layer A: Deterministic features
    pub layer_a: DeterministicFeatures,
    /// Layer B: Statistical anomaly scores
    pub layer_b: StatisticalAnomalyResult,
    /// Layer C: Behavior embeddings
    pub layer_c: BehaviorEmbedding,
    /// Layer D: Synthesized verdict
    pub layer_d: VerdictSynthesis,

    /// Final forensic score (0.0-1.0)
    pub forensic_score: f64,
    /// Forensic assertion (the key claim)
    pub forensic_assertion: ForensicAssertion,

    /// Provenance (for auditability)
    pub provenance: MLProvenance,
    /// Explainability report
    pub explanation: ExplainabilityReport,
}

/// Forensic assertion: confidence-weighted claim about behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicAssertion {
    /// The claim: "anomalous", "hostile", "benign", "uncertain"
    pub claim: String,
    /// Confidence in the claim (0.0-1.0)
    pub confidence: f64,
    /// Evidence strength (0.0-1.0)
    pub evidence_strength: f64,
    /// Supporting indicators
    pub indicators: Vec<ForensicIndicator>,
}

/// Individual forensic indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicIndicator {
    /// Indicator type: "deterministic", "statistical", "behavioral", "policy"
    pub indicator_type: String,
    /// Human-readable description
    pub description: String,
    /// Contribution to final score
    pub contribution: f64,
    /// Source layer (A, B, C, D)
    pub source_layer: char,
    /// Evidence hash (for provenance)
    pub evidence_hash: String,
}

/// ML Provenance for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLProvenance {
    /// Engine version
    pub engine_version: String,
    /// Engine version hash
    pub engine_hash: String,
    /// Model versions used
    pub model_versions: ModelVersions,
    /// Model versions combined hash
    pub model_hash: String,
    /// Input feature vector hash
    pub feature_hash: String,
    /// Verdict weights hash
    pub weights_hash: String,
    /// Decision rule used
    pub decision_rule: String,
    /// Random seed (for determinism verification)
    pub random_seed: u64,
    /// Computation timestamp
    pub computed_at: String,
}

/// Explainability report (required for sealing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainabilityReport {
    /// Top contributing features
    pub top_features: Vec<FeatureExplanation>,
    /// Graph edges that drove anomaly
    pub graph_edges: Vec<GraphEdgeExplanation>,
    /// Temporal sequence deviations
    pub temporal_deviations: Vec<TemporalDeviation>,
    /// Policy constraints violated
    pub policy_violations: Vec<PolicyViolation>,
    /// Overall explainability score (0.0-1.0)
    pub explainability_score: f64,
    /// Whether explanation meets requirements
    pub meets_requirements: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureExplanation {
    pub feature_name: String,
    pub value: f64,
    pub expected_range: (f64, f64),
    pub deviation: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdgeExplanation {
    pub edge_type: String,
    pub src: String,
    pub dst: String,
    pub anomaly_score: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalDeviation {
    pub sequence_id: String,
    pub expected_pattern: String,
    pub observed_pattern: String,
    pub deviation_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub policy_id: String,
    pub policy_name: String,
    pub constraint: String,
    pub violation_details: String,
    pub severity: f64,
}

/// Forensic ML Engine
pub struct ForensicMLEngine {
    config: ForensicMLConfig,
}

impl ForensicMLEngine {
    pub fn new(config: ForensicMLConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(ForensicMLConfig::default())
    }

    /// Analyze a window and produce forensic ML result
    pub fn analyze(
        &self,
        namespace_id: &str,
        window_id: &str,
        events: &[common_models::TraceEvent],
        attack_graph: &serde_json::Value,
    ) -> Result<ForensicMLResult, ForensicMLError> {
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Layer A: Deterministic feature extraction
        let layer_a = layer_a::extract_deterministic_features(events, attack_graph);

        // Layer B: Statistical anomaly detection
        let layer_b = layer_b::compute_anomaly_scores(&layer_a, &self.config.thresholds);

        // Layer C: Behavior embeddings
        let layer_c =
            layer_c::compute_embeddings(events, attack_graph, &self.config.model_versions);

        // Layer D: Verdict synthesis
        let layer_d =
            layer_d::synthesize_verdict(&layer_a, &layer_b, &layer_c, &self.config.weights);

        // Compute forensic score
        let forensic_score = self.compute_forensic_score(&layer_a, &layer_b, &layer_c, &layer_d);

        // Generate forensic assertion
        let forensic_assertion =
            self.generate_assertion(forensic_score, &layer_a, &layer_b, &layer_d);

        // Build provenance
        let provenance = self.build_provenance(&layer_a);

        // Generate explainability report
        let explanation = self.generate_explanation(&layer_a, &layer_b, &layer_c, &layer_d);

        // Validate explainability requirements
        if !explanation.meets_requirements {
            return Err(ForensicMLError::InsufficientExplainability(
                explanation.explainability_score,
            ));
        }

        let result_id = self.compute_result_id(namespace_id, window_id, &timestamp, forensic_score);

        Ok(ForensicMLResult {
            result_id,
            timestamp,
            namespace_id: namespace_id.to_string(),
            window_id: window_id.to_string(),
            layer_a,
            layer_b,
            layer_c,
            layer_d,
            forensic_score,
            forensic_assertion,
            provenance,
            explanation,
        })
    }

    fn compute_forensic_score(
        &self,
        layer_a: &DeterministicFeatures,
        layer_b: &StatisticalAnomalyResult,
        layer_c: &BehaviorEmbedding,
        layer_d: &VerdictSynthesis,
    ) -> f64 {
        // Per spec: verdict_score = w1*det + w2*anomaly + w3*similarity + w4*policy
        let w = &self.config.weights;
        (w.w1_deterministic * layer_a.risk_score
            + w.w2_anomaly * layer_b.combined_score
            + w.w3_similarity * layer_c.similarity_risk
            + w.w4_policy * layer_d.policy_score)
            .clamp(0.0, 1.0)
    }

    fn generate_assertion(
        &self,
        score: f64,
        layer_a: &DeterministicFeatures,
        layer_b: &StatisticalAnomalyResult,
        layer_d: &VerdictSynthesis,
    ) -> ForensicAssertion {
        let (claim, confidence) = if score >= 0.85 {
            ("hostile".to_string(), 0.95)
        } else if score >= 0.65 {
            ("anomalous".to_string(), 0.80)
        } else if score >= 0.40 {
            ("uncertain".to_string(), 0.50)
        } else {
            ("benign".to_string(), 0.85)
        };

        let evidence_strength = (layer_a.evidence_count as f64 / 100.0).min(1.0);

        let mut indicators = Vec::new();

        // Add top indicators from each layer
        for (name, value) in &layer_a.top_features {
            indicators.push(ForensicIndicator {
                indicator_type: "deterministic".to_string(),
                description: format!("{name}: {value:.2}"),
                contribution: value * self.config.weights.w1_deterministic,
                source_layer: 'A',
                evidence_hash: layer_a.feature_hash.clone(),
            });
        }

        if layer_b.is_anomaly {
            indicators.push(ForensicIndicator {
                indicator_type: "statistical".to_string(),
                description: format!("Anomaly detected (score: {:.2})", layer_b.combined_score),
                contribution: layer_b.combined_score * self.config.weights.w2_anomaly,
                source_layer: 'B',
                evidence_hash: layer_b.result_hash.clone(),
            });
        }

        for violation in &layer_d.policy_violations {
            indicators.push(ForensicIndicator {
                indicator_type: "policy".to_string(),
                description: violation.clone(),
                contribution: layer_d.policy_score * self.config.weights.w4_policy
                    / layer_d.policy_violations.len().max(1) as f64,
                source_layer: 'D',
                evidence_hash: layer_d.verdict_hash.clone(),
            });
        }

        ForensicAssertion {
            claim,
            confidence,
            evidence_strength,
            indicators,
        }
    }

    fn build_provenance(&self, layer_a: &DeterministicFeatures) -> MLProvenance {
        MLProvenance {
            engine_version: ENGINE_VERSION.to_string(),
            engine_hash: engine_version_hash(),
            model_versions: self.config.model_versions.clone(),
            model_hash: self.config.model_versions.combined_hash(),
            feature_hash: layer_a.feature_hash.clone(),
            weights_hash: self.config.weights.version_hash(),
            decision_rule: "weighted_synthesis_v1".to_string(),
            random_seed: DETERMINISTIC_SEED,
            computed_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn generate_explanation(
        &self,
        layer_a: &DeterministicFeatures,
        layer_b: &StatisticalAnomalyResult,
        layer_c: &BehaviorEmbedding,
        layer_d: &VerdictSynthesis,
    ) -> ExplainabilityReport {
        let mut top_features = Vec::new();
        for (name, value) in &layer_a.top_features {
            top_features.push(FeatureExplanation {
                feature_name: name.clone(),
                value: *value,
                expected_range: (0.0, 0.5),
                deviation: (*value - 0.25).abs(),
                contribution: *value * self.config.weights.w1_deterministic,
            });
        }

        let graph_edges: Vec<GraphEdgeExplanation> = layer_a
            .anomalous_edges
            .iter()
            .map(|e| GraphEdgeExplanation {
                edge_type: e.edge_type.clone(),
                src: e.src.clone(),
                dst: e.dst.clone(),
                anomaly_score: e.anomaly_score,
                reason: e.reason.clone(),
            })
            .collect();

        let temporal_deviations: Vec<TemporalDeviation> = layer_b
            .temporal_anomalies
            .iter()
            .map(|t| TemporalDeviation {
                sequence_id: t.sequence_id.clone(),
                expected_pattern: t.expected.clone(),
                observed_pattern: t.observed.clone(),
                deviation_score: t.deviation,
            })
            .collect();

        let policy_violations: Vec<PolicyViolation> = layer_d
            .policy_violations
            .iter()
            .enumerate()
            .map(|(i, v)| PolicyViolation {
                policy_id: format!("pol_{i}"),
                policy_name: "security_policy".to_string(),
                constraint: v.clone(),
                violation_details: v.clone(),
                severity: layer_d.policy_score / layer_d.policy_violations.len().max(1) as f64,
            })
            .collect();

        let explainability_score = self.calculate_explainability_score(
            &top_features,
            &graph_edges,
            &temporal_deviations,
            &policy_violations,
        );

        let meets_requirements = top_features.len()
            >= self.config.explainability.min_feature_contributions
            && (!self.config.explainability.require_graph_edges
                || !graph_edges.is_empty()
                || layer_a.anomalous_edges.is_empty())
            && (!self.config.explainability.require_temporal_deviations
                || !temporal_deviations.is_empty()
                || layer_b.temporal_anomalies.is_empty())
            && explainability_score >= 0.5;

        ExplainabilityReport {
            top_features,
            graph_edges,
            temporal_deviations,
            policy_violations,
            explainability_score,
            meets_requirements,
        }
    }

    fn calculate_explainability_score(
        &self,
        features: &[FeatureExplanation],
        edges: &[GraphEdgeExplanation],
        temporal: &[TemporalDeviation],
        policy: &[PolicyViolation],
    ) -> f64 {
        let feature_score = (features.len() as f64
            / self.config.explainability.min_feature_contributions as f64)
            .min(1.0);
        let edge_score = if edges.is_empty() { 0.5 } else { 1.0 };
        let temporal_score = if temporal.is_empty() { 0.5 } else { 1.0 };
        let policy_score = if policy.is_empty() { 0.5 } else { 1.0 };

        feature_score * 0.4 + edge_score * 0.2 + temporal_score * 0.2 + policy_score * 0.2
    }

    fn compute_result_id(&self, ns: &str, win: &str, ts: &str, score: f64) -> String {
        let mut h = Sha256::new();
        h.update(b"ritma-forensic-ml-result@0.1:");
        h.update(ns.as_bytes());
        h.update(b":");
        h.update(win.as_bytes());
        h.update(b":");
        h.update(ts.as_bytes());
        h.update(b":");
        h.update(score.to_le_bytes());
        format!("fml_{}", &hex::encode(h.finalize())[..32])
    }

    /// Get config hash for provenance
    pub fn config_hash(&self) -> String {
        let json = serde_json::to_string(&self.config).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(b"ritma-forensic-ml-config@0.1:");
        h.update(json.as_bytes());
        hex::encode(h.finalize())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ForensicMLError {
    #[error("insufficient explainability: score {0:.2} below threshold")]
    InsufficientExplainability(f64),
    #[error("model not trained: {0}")]
    ModelNotTrained(String),
    #[error("feature extraction failed: {0}")]
    FeatureExtraction(String),
    #[error("consensus seal required but not obtained")]
    ConsensusSealRequired,
    #[error("notarization failed: {0}")]
    NotarizationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_version_hash_determinism() {
        let h1 = engine_version_hash();
        let h2 = engine_version_hash();
        assert_eq!(h1, h2, "Engine version hash must be deterministic");
    }

    #[test]
    fn test_weights_hash_determinism() {
        let w = VerdictWeights::default();
        let h1 = w.version_hash();
        let h2 = w.version_hash();
        assert_eq!(h1, h2, "Weights hash must be deterministic");
    }

    #[test]
    fn test_default_config() {
        let config = ForensicMLConfig::default();
        assert!(config.weights.w1_deterministic > 0.0);
        assert!(config.weights.w2_anomaly > 0.0);
        assert!(config.weights.w3_similarity > 0.0);
        assert!(config.weights.w4_policy > 0.0);

        let total = config.weights.w1_deterministic
            + config.weights.w2_anomaly
            + config.weights.w3_similarity
            + config.weights.w4_policy;
        assert!((total - 1.0).abs() < 0.01, "Weights should sum to ~1.0");
    }
}
