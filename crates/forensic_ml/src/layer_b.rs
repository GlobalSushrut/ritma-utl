//! Layer B: Statistical Anomaly Models (Classical ML)
//!
//! Stable, interpretable, deterministic models:
//! - Isolation Forest
//! - Local Outlier Factor (LOF)
//! - Robust PCA
//! - HMM for sequences

use crate::layer_a::DeterministicFeatures;
use crate::AnomalyThresholds;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Statistical anomaly detection results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalAnomalyResult {
    /// Result hash for provenance
    pub result_hash: String,
    /// Combined anomaly score (0.0-1.0)
    pub combined_score: f64,
    /// Whether anomaly detected
    pub is_anomaly: bool,

    /// Isolation Forest result
    pub isolation_forest: IsolationForestResult,
    /// Local Outlier Factor result
    pub lof: LOFResult,
    /// Statistical baseline result
    pub baseline: BaselineResult,
    /// HMM sequence result
    pub hmm: HMMResult,

    /// Temporal anomalies detected
    pub temporal_anomalies: Vec<TemporalAnomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForestResult {
    pub score: f64,
    pub is_anomaly: bool,
    pub path_length: f64,
    pub contributing_features: Vec<(String, f64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LOFResult {
    pub score: f64,
    pub is_anomaly: bool,
    pub k_distance: f64,
    pub local_reachability_density: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineResult {
    pub score: f64,
    pub is_anomaly: bool,
    pub deviations: Vec<FeatureDeviation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureDeviation {
    pub feature_name: String,
    pub value: f64,
    pub mean: f64,
    pub std_dev: f64,
    pub z_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HMMResult {
    pub score: f64,
    pub is_anomaly: bool,
    pub log_likelihood: f64,
    pub state_sequence: Vec<i32>,
    pub transition_anomalies: Vec<TransitionAnomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionAnomaly {
    pub from_state: i32,
    pub to_state: i32,
    pub probability: f64,
    pub expected_probability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalAnomaly {
    pub sequence_id: String,
    pub expected: String,
    pub observed: String,
    pub deviation: f64,
}

/// Compute statistical anomaly scores from deterministic features
pub fn compute_anomaly_scores(
    features: &DeterministicFeatures,
    thresholds: &AnomalyThresholds,
) -> StatisticalAnomalyResult {
    // Isolation Forest
    let isolation_forest = compute_isolation_forest(features, thresholds.isolation_forest);

    // Local Outlier Factor
    let lof = compute_lof(features, thresholds.lof);

    // Statistical Baseline
    let baseline = compute_baseline(features, thresholds.baseline_std);

    // HMM sequence analysis
    let hmm = compute_hmm(features);

    // Temporal anomalies
    let temporal_anomalies = detect_temporal_anomalies(features);

    // Combined score (weighted average)
    let combined_score = (isolation_forest.score * 0.35
        + lof.score * 0.25
        + baseline.score * 0.25
        + hmm.score * 0.15)
        .clamp(0.0, 1.0);

    let is_anomaly = combined_score > 0.5 || isolation_forest.is_anomaly || lof.is_anomaly;

    let result_hash = compute_result_hash(&isolation_forest, &lof, &baseline, &hmm);

    StatisticalAnomalyResult {
        result_hash,
        combined_score,
        is_anomaly,
        isolation_forest,
        lof,
        baseline,
        hmm,
        temporal_anomalies,
    }
}

fn compute_isolation_forest(
    features: &DeterministicFeatures,
    threshold: f64,
) -> IsolationForestResult {
    // Feature vector for isolation forest
    let feature_vec = [features.process_graph.fork_fan_out,
        features.process_graph.diversity,
        features.temporal_causality.burst_score,
        features.entropy.rarity_score,
        features.privilege_transitions.transition_score,
        features.io_flow.exfil_indicator];

    // Simplified isolation forest score calculation
    // In production, this would use trained isolation forest model
    let mut path_lengths: Vec<f64> = Vec::new();

    // Deterministic "tree" simulation using feature values
    for (i, &val) in feature_vec.iter().enumerate() {
        // Path length inversely related to how extreme the value is
        let normalized = val.clamp(0.0, 1.0);
        let path_len = if normalized > 0.7 {
            2.0 + (1.0 - normalized) * 5.0 // Short path for anomalies
        } else {
            5.0 + normalized * 3.0 // Longer path for normal
        };
        path_lengths.push(path_len);
    }

    let avg_path_length = path_lengths.iter().sum::<f64>() / path_lengths.len() as f64;

    // Isolation Forest score: 2^(-E(h(x))/c(n))
    // Simplified: normalize path length to 0-1 anomaly score
    let c_n = 8.0; // Expected path length for normal instances
    let score = (2.0_f64.powf(-avg_path_length / c_n)).clamp(0.0, 1.0);

    let contributing_features: Vec<(String, f64)> = vec![
        (
            "fork_fan_out".to_string(),
            features.process_graph.fork_fan_out,
        ),
        (
            "burst_score".to_string(),
            features.temporal_causality.burst_score,
        ),
        (
            "priv_transition".to_string(),
            features.privilege_transitions.transition_score,
        ),
    ];

    IsolationForestResult {
        score,
        is_anomaly: score > threshold,
        path_length: avg_path_length,
        contributing_features,
    }
}

fn compute_lof(features: &DeterministicFeatures, threshold: f64) -> LOFResult {
    // Local Outlier Factor computation
    // Simplified: compare to expected baseline values

    let expected_values = vec![
        ("fork_fan_out", 0.1, 0.05), // (name, expected_mean, expected_std)
        ("diversity", 0.3, 0.1),
        ("burst_score", 0.2, 0.1),
        ("rarity", 0.3, 0.15),
        ("priv_trans", 0.05, 0.03),
        ("exfil", 0.1, 0.05),
    ];

    let actual_values = [features.process_graph.fork_fan_out,
        features.process_graph.diversity,
        features.temporal_causality.burst_score,
        features.entropy.rarity_score,
        features.privilege_transitions.transition_score,
        features.io_flow.exfil_indicator];

    // K-distance approximation (distance to kth nearest neighbor in feature space)
    let mut total_deviation = 0.0;
    for (i, &val) in actual_values.iter().enumerate() {
        let (_, mean, std) = expected_values[i];
        let z = if std > 0.0 {
            (val - mean).abs() / std
        } else {
            0.0
        };
        total_deviation += z;
    }

    let k_distance = total_deviation / actual_values.len() as f64;

    // Local reachability density (inverse of average reachability distance)
    let lrd = if k_distance > 0.0 {
        1.0 / k_distance
    } else {
        10.0
    };

    // LOF score: ratio of average LRD of neighbors to point's LRD
    // Simplified: normalize k_distance to LOF-like score
    let score = (k_distance / 3.0).clamp(0.0, 1.0);

    LOFResult {
        score,
        is_anomaly: k_distance > threshold,
        k_distance,
        local_reachability_density: lrd,
    }
}

fn compute_baseline(features: &DeterministicFeatures, std_threshold: f64) -> BaselineResult {
    // Compare against statistical baseline
    let baselines = vec![
        (
            "process_count",
            features.process_graph.process_count as f64,
            50.0,
            30.0,
        ),
        (
            "max_depth",
            features.process_graph.max_depth as f64,
            5.0,
            2.0,
        ),
        (
            "event_rate",
            features.temporal_causality.event_rate,
            5.0,
            3.0,
        ),
        (
            "net_connections",
            features.io_flow.net_connections as f64,
            10.0,
            8.0,
        ),
        ("file_ops", features.io_flow.file_ops as f64, 20.0, 15.0),
    ];

    let mut deviations = Vec::new();
    let mut total_z = 0.0;

    for (name, value, mean, std) in baselines {
        let z_score = if std > 0.0 { (value - mean) / std } else { 0.0 };
        total_z += z_score.abs();

        if z_score.abs() > 2.0 {
            deviations.push(FeatureDeviation {
                feature_name: name.to_string(),
                value,
                mean,
                std_dev: std,
                z_score,
            });
        }
    }

    let avg_z = total_z / 5.0;
    let score = (avg_z / std_threshold).clamp(0.0, 1.0);

    BaselineResult {
        score,
        is_anomaly: avg_z > std_threshold,
        deviations,
    }
}

fn compute_hmm(features: &DeterministicFeatures) -> HMMResult {
    // Hidden Markov Model for sequence analysis
    // States: 0=idle, 1=normal_activity, 2=elevated_activity, 3=anomalous

    // Determine state sequence based on features
    let mut states = Vec::new();
    let mut transition_anomalies = Vec::new();

    // Simplified state assignment based on activity levels
    let activity_level = features.temporal_causality.event_rate;
    let privilege_level = features.privilege_transitions.transition_score;
    let io_level = features.io_flow.exfil_indicator;

    // Assign states based on thresholds
    let state = if activity_level < 1.0 && privilege_level < 0.1 {
        0 // Idle
    } else if activity_level < 5.0 && privilege_level < 0.3 && io_level < 0.3 {
        1 // Normal
    } else if privilege_level > 0.5 || io_level > 0.5 {
        3 // Anomalous
    } else {
        2 // Elevated
    };

    states.push(state);

    // Check for unexpected transitions
    // Expected: 0->1, 1->2, 2->1, 1->0
    // Anomalous: 0->3, 1->3 (direct jump to anomalous)
    if state == 3 {
        transition_anomalies.push(TransitionAnomaly {
            from_state: 1,
            to_state: 3,
            probability: 0.05,
            expected_probability: 0.01,
        });
    }

    // Log likelihood (higher = more likely under normal model)
    let log_likelihood: f64 = match state {
        0 => -1.0,
        1 => -0.5,
        2 => -2.0,
        3 => -5.0,
        _ => -3.0,
    };

    // Score based on how unlikely the sequence is
    let score: f64 = ((-log_likelihood - 0.5) / 5.0).clamp(0.0, 1.0);

    HMMResult {
        score,
        is_anomaly: state == 3,
        log_likelihood,
        state_sequence: states,
        transition_anomalies,
    }
}

fn detect_temporal_anomalies(features: &DeterministicFeatures) -> Vec<TemporalAnomaly> {
    let mut anomalies = Vec::new();

    // Check for burst activity anomaly
    if features.temporal_causality.burst_score > 0.7 {
        anomalies.push(TemporalAnomaly {
            sequence_id: "burst_detection".to_string(),
            expected: "event_rate < 10/s".to_string(),
            observed: format!(
                "event_rate = {:.1}/s",
                features.temporal_causality.event_rate
            ),
            deviation: features.temporal_causality.burst_score,
        });
    }

    // Check for timing anomalies
    if features.temporal_causality.timing_anomalies > 0 {
        anomalies.push(TemporalAnomaly {
            sequence_id: "timing_order".to_string(),
            expected: "events in causal order".to_string(),
            observed: format!(
                "{} out-of-order events",
                features.temporal_causality.timing_anomalies
            ),
            deviation: features.temporal_causality.timing_anomalies as f64 / 10.0,
        });
    }

    anomalies
}

fn compute_result_hash(
    iforest: &IsolationForestResult,
    lof: &LOFResult,
    baseline: &BaselineResult,
    hmm: &HMMResult,
) -> String {
    let mut h = Sha256::new();
    h.update(b"ritma-layer-b-result@0.1:");
    h.update(iforest.score.to_le_bytes());
    h.update(lof.score.to_le_bytes());
    h.update(baseline.score.to_le_bytes());
    h.update(hmm.score.to_le_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer_a::*;

    fn mock_features() -> DeterministicFeatures {
        DeterministicFeatures {
            feature_hash: "test".to_string(),
            risk_score: 0.5,
            evidence_count: 100,
            top_features: vec![],
            process_graph: ProcessGraphMetrics {
                process_count: 50,
                max_depth: 5,
                diversity: 0.3,
                orphan_count: 2,
                fork_fan_out: 0.1,
                novel_lineage: 10,
            },
            temporal_causality: TemporalCausalityMetrics {
                causal_chain_length: 100,
                timing_anomalies: 0,
                burst_score: 0.2,
                window_duration_secs: 60.0,
                event_rate: 1.67,
            },
            entropy: EntropyMetrics {
                command_entropy: 0.5,
                path_entropy: 0.4,
                network_entropy: 0.3,
                rarity_score: 0.4,
            },
            privilege_transitions: PrivilegeMetrics {
                escalation_count: 0,
                drop_count: 0,
                setuid_count: 0,
                root_process_count: 5,
                transition_score: 0.05,
            },
            io_flow: IOFlowMetrics {
                file_ops: 20,
                net_connections: 10,
                novel_destinations: 3,
                exfil_indicator: 0.1,
                sensitive_access: 0,
            },
            anomalous_edges: vec![],
        }
    }

    #[test]
    fn test_compute_anomaly_scores() {
        let features = mock_features();
        let thresholds = AnomalyThresholds::default();
        let result = compute_anomaly_scores(&features, &thresholds);

        assert!(result.combined_score >= 0.0 && result.combined_score <= 1.0);
        assert!(!result.result_hash.is_empty());
    }
}
