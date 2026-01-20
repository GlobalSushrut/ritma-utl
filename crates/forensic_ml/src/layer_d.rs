//! Layer D: Verdict Synthesis Layer
//!
//! Rule-governed aggregation of all layers:
//! verdict_score = w1*det + w2*anomaly + w3*similarity + w4*policy
//!
//! Weights and formula are versioned and logged.

use crate::layer_a::DeterministicFeatures;
use crate::layer_b::StatisticalAnomalyResult;
use crate::layer_c::BehaviorEmbedding;
use crate::VerdictWeights;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Verdict synthesis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictSynthesis {
    /// Verdict hash for provenance
    pub verdict_hash: String,
    /// Weights used (version hash)
    pub weights_hash: String,
    /// Decision rule used
    pub decision_rule: String,

    /// Final synthesized score (0.0-1.0)
    pub synthesized_score: f64,
    /// Verdict classification
    pub verdict: VerdictClass,
    /// Confidence level
    pub confidence: f64,

    /// Policy score component
    pub policy_score: f64,
    /// Policy violations detected
    pub policy_violations: Vec<String>,

    /// Component scores (for explainability)
    pub component_scores: ComponentScores,
    /// Decision rationale
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictClass {
    Benign,
    Suspicious,
    Anomalous,
    Hostile,
}

impl VerdictClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerdictClass::Benign => "benign",
            VerdictClass::Suspicious => "suspicious",
            VerdictClass::Anomalous => "anomalous",
            VerdictClass::Hostile => "hostile",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentScores {
    /// Deterministic evidence score (Layer A)
    pub deterministic: f64,
    /// Anomaly detection score (Layer B)
    pub anomaly: f64,
    /// Similarity risk score (Layer C)
    pub similarity: f64,
    /// Policy violation score
    pub policy: f64,
    /// Weighted contributions
    pub weighted_deterministic: f64,
    pub weighted_anomaly: f64,
    pub weighted_similarity: f64,
    pub weighted_policy: f64,
}

/// Synthesize final verdict from all layers
pub fn synthesize_verdict(
    layer_a: &DeterministicFeatures,
    layer_b: &StatisticalAnomalyResult,
    layer_c: &BehaviorEmbedding,
    weights: &VerdictWeights,
) -> VerdictSynthesis {
    // Extract component scores
    let det_score = layer_a.risk_score;
    let anomaly_score = layer_b.combined_score;
    let similarity_score = layer_c.similarity_risk;

    // Evaluate policy violations
    let (policy_score, policy_violations) = evaluate_policies(layer_a, layer_b, layer_c);

    // Compute weighted synthesis
    let weighted_det = weights.w1_deterministic * det_score;
    let weighted_anomaly = weights.w2_anomaly * anomaly_score;
    let weighted_similarity = weights.w3_similarity * similarity_score;
    let weighted_policy = weights.w4_policy * policy_score;

    let synthesized_score =
        (weighted_det + weighted_anomaly + weighted_similarity + weighted_policy).clamp(0.0, 1.0);

    // Determine verdict class
    let (verdict, confidence) =
        classify_verdict(synthesized_score, layer_b.is_anomaly, &policy_violations);

    // Build rationale
    let rationale = build_rationale(
        &verdict,
        det_score,
        anomaly_score,
        similarity_score,
        policy_score,
        &policy_violations,
    );

    let component_scores = ComponentScores {
        deterministic: det_score,
        anomaly: anomaly_score,
        similarity: similarity_score,
        policy: policy_score,
        weighted_deterministic: weighted_det,
        weighted_anomaly,
        weighted_similarity,
        weighted_policy,
    };

    let verdict_hash = compute_verdict_hash(synthesized_score, &verdict, &policy_violations);

    VerdictSynthesis {
        verdict_hash,
        weights_hash: weights.version_hash(),
        decision_rule: "weighted_synthesis_v1".to_string(),
        synthesized_score,
        verdict,
        confidence,
        policy_score,
        policy_violations,
        component_scores,
        rationale,
    }
}

fn evaluate_policies(
    layer_a: &DeterministicFeatures,
    layer_b: &StatisticalAnomalyResult,
    layer_c: &BehaviorEmbedding,
) -> (f64, Vec<String>) {
    let mut violations = Vec::new();
    let mut policy_score: f64 = 0.0;

    // Policy 1: Privilege escalation detection
    if layer_a.privilege_transitions.escalation_count > 0 {
        violations.push(format!(
            "PRIV_ESCALATION: {} privilege escalations detected",
            layer_a.privilege_transitions.escalation_count
        ));
        policy_score += 0.3;
    }

    // Policy 2: Excessive root process execution
    if layer_a.privilege_transitions.root_process_count > 10 {
        violations.push(format!(
            "EXCESSIVE_ROOT: {} root processes (threshold: 10)",
            layer_a.privilege_transitions.root_process_count
        ));
        policy_score += 0.2;
    }

    // Policy 3: Data exfiltration indicator
    if layer_a.io_flow.exfil_indicator > 0.5 {
        violations.push(format!(
            "EXFIL_INDICATOR: score {:.2} (threshold: 0.5)",
            layer_a.io_flow.exfil_indicator
        ));
        policy_score += 0.3;
    }

    // Policy 4: Sensitive file access
    if layer_a.io_flow.sensitive_access > 0 {
        violations.push(format!(
            "SENSITIVE_ACCESS: {} accesses to sensitive files",
            layer_a.io_flow.sensitive_access
        ));
        policy_score += 0.2;
    }

    // Policy 5: Burst activity
    if layer_a.temporal_causality.burst_score > 0.7 {
        violations.push(format!(
            "BURST_ACTIVITY: event rate {:.1}/s (burst threshold exceeded)",
            layer_a.temporal_causality.event_rate
        ));
        policy_score += 0.15;
    }

    // Policy 6: HMM anomalous state
    if layer_b.hmm.is_anomaly {
        violations.push("HMM_ANOMALY: behavior sequence in anomalous state".to_string());
        policy_score += 0.25;
    }

    // Policy 7: Malware pattern similarity
    for pattern in &layer_c.similar_patterns {
        if pattern.category == "malware" && pattern.similarity > 0.6 {
            violations.push(format!(
                "MALWARE_PATTERN: {:.0}% similar to '{}'",
                pattern.similarity * 100.0,
                pattern.pattern_name
            ));
            policy_score += 0.3;
            break; // Only count most similar malware pattern
        }
    }

    // Policy 8: Novel network destinations with high egress
    if layer_a.io_flow.novel_destinations > 5 && layer_a.io_flow.net_connections > 20 {
        violations.push(format!(
            "NOVEL_EGRESS: {} novel destinations with {} connections",
            layer_a.io_flow.novel_destinations, layer_a.io_flow.net_connections
        ));
        policy_score += 0.2;
    }

    (policy_score.clamp(0.0_f64, 1.0_f64), violations)
}

fn classify_verdict(score: f64, is_anomaly: bool, violations: &[String]) -> (VerdictClass, f64) {
    // Classification thresholds (versioned decision rule)
    let (verdict, base_confidence) = if score >= 0.80 || (is_anomaly && violations.len() >= 3) {
        (VerdictClass::Hostile, 0.90)
    } else if score >= 0.60 || (is_anomaly && violations.len() >= 2) {
        (VerdictClass::Anomalous, 0.80)
    } else if score >= 0.35 || !violations.is_empty() {
        (VerdictClass::Suspicious, 0.70)
    } else {
        (VerdictClass::Benign, 0.85)
    };

    // Adjust confidence based on evidence strength
    let evidence_factor = 1.0 - (0.5 - score).abs() * 0.2; // Higher confidence at extremes
    let confidence = (base_confidence * evidence_factor).clamp(0.5, 0.99);

    (verdict, confidence)
}

fn build_rationale(
    verdict: &VerdictClass,
    det_score: f64,
    anomaly_score: f64,
    similarity_score: f64,
    policy_score: f64,
    violations: &[String],
) -> Vec<String> {
    let mut rationale = Vec::new();

    rationale.push(format!(
        "Verdict: {} based on weighted synthesis",
        verdict.as_str().to_uppercase()
    ));

    rationale.push(format!(
        "Component scores: deterministic={det_score:.2}, anomaly={anomaly_score:.2}, similarity={similarity_score:.2}, policy={policy_score:.2}"
    ));

    // Explain dominant factors
    let max_score = det_score
        .max(anomaly_score)
        .max(similarity_score)
        .max(policy_score);
    if max_score == det_score && det_score > 0.4 {
        rationale.push(
            "Primary driver: deterministic evidence (graph/temporal/privilege patterns)"
                .to_string(),
        );
    }
    if max_score == anomaly_score && anomaly_score > 0.4 {
        rationale.push("Primary driver: statistical anomaly detection (IF/LOF/HMM)".to_string());
    }
    if max_score == similarity_score && similarity_score > 0.4 {
        rationale.push("Primary driver: behavior similarity to known threats".to_string());
    }
    if max_score == policy_score && policy_score > 0.3 {
        rationale.push("Primary driver: policy violations detected".to_string());
    }

    // Add violation summary
    if !violations.is_empty() {
        rationale.push(format!(
            "Policy violations ({}): {}",
            violations.len(),
            violations.join("; ")
        ));
    }

    rationale
}

fn compute_verdict_hash(score: f64, verdict: &VerdictClass, violations: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(b"ritma-layer-d-verdict@0.1:");
    h.update(score.to_le_bytes());
    h.update(verdict.as_str().as_bytes());
    for v in violations {
        h.update(v.as_bytes());
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_classification() {
        let (verdict, _) = classify_verdict(0.9, true, &["violation".to_string()]);
        assert_eq!(verdict, VerdictClass::Hostile);

        let (verdict, _) = classify_verdict(0.1, false, &[]);
        assert_eq!(verdict, VerdictClass::Benign);
    }
}
