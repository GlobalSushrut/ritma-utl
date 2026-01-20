//! ML-based Anomaly Detection (Q1.5)
//!
//! Machine learning anomaly detection for security events:
//! - Isolation Forest for outlier detection
//! - Statistical baseline learning
//! - Time-series anomaly detection
//! - Behavioral profiling

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnomalyError {
    #[error("model not trained")]
    NotTrained,
    #[error("insufficient data: need {0} samples, have {1}")]
    InsufficientData(usize, usize),
    #[error("invalid feature: {0}")]
    InvalidFeature(String),
}

/// Feature vector for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub timestamp: i64,
    pub entity_id: String,
    pub features: Vec<f64>,
    pub feature_names: Vec<String>,
}

impl FeatureVector {
    pub fn new(entity_id: &str, timestamp: i64) -> Self {
        Self {
            timestamp,
            entity_id: entity_id.to_string(),
            features: Vec::new(),
            feature_names: Vec::new(),
        }
    }

    pub fn add_feature(&mut self, name: &str, value: f64) {
        self.feature_names.push(name.to_string());
        self.features.push(value);
    }

    pub fn dimension(&self) -> usize {
        self.features.len()
    }
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    pub result_id: [u8; 32],
    pub timestamp: i64,
    pub entity_id: String,
    pub anomaly_score: f64,
    pub is_anomaly: bool,
    pub threshold: f64,
    pub contributing_features: Vec<FeatureContribution>,
    pub model_type: ModelType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureContribution {
    pub feature_name: String,
    pub value: f64,
    pub expected_range: (f64, f64),
    pub contribution_score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelType {
    IsolationForest,
    StatisticalBaseline,
    TimeSeries,
    Ensemble,
}

impl AnomalyResult {
    pub fn new(
        entity_id: &str,
        timestamp: i64,
        score: f64,
        threshold: f64,
        model_type: ModelType,
    ) -> Self {
        let result_id = Self::compute_id(entity_id, timestamp, score);
        Self {
            result_id,
            timestamp,
            entity_id: entity_id.to_string(),
            anomaly_score: score,
            is_anomaly: score > threshold,
            threshold,
            contributing_features: Vec::new(),
            model_type,
        }
    }

    fn compute_id(entity_id: &str, timestamp: i64, score: f64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-anomaly@0.1");
        h.update(entity_id.as_bytes());
        h.update(timestamp.to_le_bytes());
        h.update(score.to_le_bytes());
        h.finalize().into()
    }

    pub fn result_id_hex(&self) -> String {
        hex::encode(self.result_id)
    }
}

/// Isolation Forest node
#[derive(Debug, Clone)]
enum IsolationNode {
    Internal {
        split_feature: usize,
        split_value: f64,
        left: Box<IsolationNode>,
        right: Box<IsolationNode>,
    },
    Leaf {
        size: usize,
    },
}

/// Isolation Tree
#[derive(Debug, Clone)]
struct IsolationTree {
    root: IsolationNode,
    height_limit: usize,
}

impl IsolationTree {
    fn build(data: &[&FeatureVector], height_limit: usize, current_height: usize) -> IsolationNode {
        if current_height >= height_limit || data.len() <= 1 {
            return IsolationNode::Leaf { size: data.len() };
        }

        if data.is_empty() {
            return IsolationNode::Leaf { size: 0 };
        }

        let n_features = data[0].dimension();
        if n_features == 0 {
            return IsolationNode::Leaf { size: data.len() };
        }

        // Random feature selection (using simple hash for determinism)
        let split_feature = (current_height * 31 + data.len() * 17) % n_features;

        // Find min/max for selected feature
        let values: Vec<f64> = data.iter().map(|v| v.features[split_feature]).collect();
        let min_val = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_val = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        if (max_val - min_val).abs() < f64::EPSILON {
            return IsolationNode::Leaf { size: data.len() };
        }

        // Random split point (using hash for determinism)
        let hash = (current_height as f64 * 0.618033988749895) % 1.0;
        let split_value = min_val + hash * (max_val - min_val);

        // Partition data
        let (left_data, right_data): (Vec<_>, Vec<_>) = data
            .iter()
            .partition(|v| v.features[split_feature] < split_value);

        IsolationNode::Internal {
            split_feature,
            split_value,
            left: Box::new(Self::build(&left_data, height_limit, current_height + 1)),
            right: Box::new(Self::build(&right_data, height_limit, current_height + 1)),
        }
    }

    fn path_length(&self, sample: &FeatureVector, current_height: usize) -> f64 {
        match &self.root {
            IsolationNode::Leaf { size } => current_height as f64 + Self::c(*size),
            IsolationNode::Internal {
                split_feature,
                split_value,
                left,
                right,
            } => {
                if sample.features.get(*split_feature).copied().unwrap_or(0.0) < *split_value {
                    Self::path_length_node(left, sample, current_height + 1)
                } else {
                    Self::path_length_node(right, sample, current_height + 1)
                }
            }
        }
    }

    fn path_length_node(
        node: &IsolationNode,
        sample: &FeatureVector,
        current_height: usize,
    ) -> f64 {
        match node {
            IsolationNode::Leaf { size } => current_height as f64 + Self::c(*size),
            IsolationNode::Internal {
                split_feature,
                split_value,
                left,
                right,
            } => {
                if sample.features.get(*split_feature).copied().unwrap_or(0.0) < *split_value {
                    Self::path_length_node(left, sample, current_height + 1)
                } else {
                    Self::path_length_node(right, sample, current_height + 1)
                }
            }
        }
    }

    /// Average path length of unsuccessful search in BST
    fn c(n: usize) -> f64 {
        if n <= 1 {
            return 0.0;
        }
        let n = n as f64;
        2.0 * (n.ln() + 0.5772156649) - (2.0 * (n - 1.0) / n)
    }
}

/// Isolation Forest anomaly detector
pub struct IsolationForest {
    trees: Vec<IsolationTree>,
    n_trees: usize,
    sample_size: usize,
    trained: bool,
    threshold: f64,
}

impl IsolationForest {
    pub fn new(n_trees: usize, sample_size: usize) -> Self {
        Self {
            trees: Vec::new(),
            n_trees,
            sample_size,
            trained: false,
            threshold: 0.5,
        }
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = threshold;
        self
    }

    /// Train the isolation forest
    pub fn fit(&mut self, data: &[FeatureVector]) -> Result<(), AnomalyError> {
        if data.len() < self.sample_size {
            return Err(AnomalyError::InsufficientData(self.sample_size, data.len()));
        }

        let height_limit = (self.sample_size as f64).log2().ceil() as usize;

        self.trees.clear();
        for i in 0..self.n_trees {
            // Sample data (using deterministic sampling for reproducibility)
            let sample: Vec<&FeatureVector> = data
                .iter()
                .enumerate()
                .filter(|(j, _)| (i * 31 + j * 17) % data.len() < self.sample_size)
                .map(|(_, v)| v)
                .take(self.sample_size)
                .collect();

            let root = IsolationTree::build(&sample, height_limit, 0);
            self.trees.push(IsolationTree { root, height_limit });
        }

        self.trained = true;
        Ok(())
    }

    /// Compute anomaly score for a sample
    pub fn score(&self, sample: &FeatureVector) -> Result<f64, AnomalyError> {
        if !self.trained {
            return Err(AnomalyError::NotTrained);
        }

        let avg_path_length: f64 = self
            .trees
            .iter()
            .map(|tree| tree.path_length(sample, 0))
            .sum::<f64>()
            / self.trees.len() as f64;

        let c = IsolationTree::c(self.sample_size);
        let score = 2.0_f64.powf(-avg_path_length / c);

        Ok(score)
    }

    /// Detect anomaly
    pub fn detect(&self, sample: &FeatureVector) -> Result<AnomalyResult, AnomalyError> {
        let score = self.score(sample)?;
        Ok(AnomalyResult::new(
            &sample.entity_id,
            sample.timestamp,
            score,
            self.threshold,
            ModelType::IsolationForest,
        ))
    }

    pub fn is_trained(&self) -> bool {
        self.trained
    }
}

/// Statistical baseline detector
pub struct StatisticalBaseline {
    /// Feature statistics: mean, std, min, max
    stats: HashMap<String, FeatureStats>,
    /// Number of samples seen
    sample_count: usize,
    /// Threshold in standard deviations
    std_threshold: f64,
}

#[derive(Debug, Clone, Default)]
struct FeatureStats {
    mean: f64,
    variance: f64,
    min: f64,
    max: f64,
    count: usize,
    m2: f64, // For Welford's algorithm
}

impl FeatureStats {
    fn std_dev(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            (self.variance / self.count as f64).sqrt()
        }
    }

    fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
        self.variance = self.m2;

        if self.count == 1 {
            self.min = value;
            self.max = value;
        } else {
            self.min = self.min.min(value);
            self.max = self.max.max(value);
        }
    }

    fn z_score(&self, value: f64) -> f64 {
        let std = self.std_dev();
        if std < f64::EPSILON {
            0.0
        } else {
            (value - self.mean).abs() / std
        }
    }
}

impl StatisticalBaseline {
    pub fn new(std_threshold: f64) -> Self {
        Self {
            stats: HashMap::new(),
            sample_count: 0,
            std_threshold,
        }
    }

    /// Update baseline with new sample
    pub fn update(&mut self, sample: &FeatureVector) {
        for (name, &value) in sample.feature_names.iter().zip(sample.features.iter()) {
            self.stats.entry(name.clone()).or_default().update(value);
        }
        self.sample_count += 1;
    }

    /// Detect anomaly
    pub fn detect(&self, sample: &FeatureVector) -> AnomalyResult {
        let mut max_z_score: f64 = 0.0;
        let mut contributions = Vec::new();

        for (name, &value) in sample.feature_names.iter().zip(sample.features.iter()) {
            if let Some(stats) = self.stats.get(name) {
                let z = stats.z_score(value);
                max_z_score = max_z_score.max(z);

                if z > self.std_threshold * 0.5 {
                    contributions.push(FeatureContribution {
                        feature_name: name.clone(),
                        value,
                        expected_range: (
                            stats.mean - 2.0 * stats.std_dev(),
                            stats.mean + 2.0 * stats.std_dev(),
                        ),
                        contribution_score: z / self.std_threshold,
                    });
                }
            }
        }

        // Normalize score to 0-1 range
        let score = (max_z_score / (self.std_threshold * 2.0)).min(1.0);

        let mut result = AnomalyResult::new(
            &sample.entity_id,
            sample.timestamp,
            score,
            0.5,
            ModelType::StatisticalBaseline,
        );
        result.contributing_features = contributions;
        result
    }

    pub fn sample_count(&self) -> usize {
        self.sample_count
    }
}

/// Time-series anomaly detector using sliding window
pub struct TimeSeriesDetector {
    /// Window of recent values per entity
    windows: HashMap<String, VecDeque<f64>>,
    /// Window size
    window_size: usize,
    /// Threshold multiplier
    threshold_mult: f64,
}

impl TimeSeriesDetector {
    pub fn new(window_size: usize, threshold_mult: f64) -> Self {
        Self {
            windows: HashMap::new(),
            window_size,
            threshold_mult,
        }
    }

    /// Add value and detect anomaly
    pub fn detect(&mut self, entity_id: &str, timestamp: i64, value: f64) -> AnomalyResult {
        let window = self
            .windows
            .entry(entity_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(self.window_size));

        // Compute stats from window
        let (mean, std) = if window.len() >= 2 {
            let sum: f64 = window.iter().sum();
            let mean = sum / window.len() as f64;
            let variance: f64 =
                window.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / window.len() as f64;
            (mean, variance.sqrt())
        } else {
            (value, 0.0)
        };

        // Compute anomaly score
        let z_score = if std > f64::EPSILON {
            (value - mean).abs() / std
        } else {
            0.0
        };

        let score = (z_score / (self.threshold_mult * 2.0)).min(1.0);

        // Update window
        if window.len() >= self.window_size {
            window.pop_front();
        }
        window.push_back(value);

        let mut result =
            AnomalyResult::new(entity_id, timestamp, score, 0.5, ModelType::TimeSeries);

        if score > 0.3 {
            result.contributing_features.push(FeatureContribution {
                feature_name: "value".to_string(),
                value,
                expected_range: (mean - 2.0 * std, mean + 2.0 * std),
                contribution_score: score,
            });
        }

        result
    }
}

/// Ensemble anomaly detector
pub struct EnsembleDetector {
    isolation_forest: Option<IsolationForest>,
    statistical_baseline: StatisticalBaseline,
    time_series: TimeSeriesDetector,
    weights: (f64, f64, f64),
}

impl EnsembleDetector {
    pub fn new() -> Self {
        Self {
            isolation_forest: None,
            statistical_baseline: StatisticalBaseline::new(3.0),
            time_series: TimeSeriesDetector::new(100, 3.0),
            weights: (0.4, 0.3, 0.3),
        }
    }

    pub fn with_weights(mut self, if_weight: f64, stat_weight: f64, ts_weight: f64) -> Self {
        let total = if_weight + stat_weight + ts_weight;
        self.weights = (if_weight / total, stat_weight / total, ts_weight / total);
        self
    }

    /// Train isolation forest component
    pub fn train_isolation_forest(&mut self, data: &[FeatureVector]) -> Result<(), AnomalyError> {
        let mut forest = IsolationForest::new(100, 256.min(data.len()));
        forest.fit(data)?;
        self.isolation_forest = Some(forest);
        Ok(())
    }

    /// Update statistical baseline
    pub fn update_baseline(&mut self, sample: &FeatureVector) {
        self.statistical_baseline.update(sample);
    }

    /// Detect anomaly using ensemble
    pub fn detect(&mut self, sample: &FeatureVector) -> AnomalyResult {
        let mut scores = Vec::new();
        let mut all_contributions = Vec::new();

        // Isolation Forest
        if let Some(ref forest) = self.isolation_forest {
            if let Ok(result) = forest.detect(sample) {
                scores.push((result.anomaly_score, self.weights.0));
            }
        }

        // Statistical Baseline
        let stat_result = self.statistical_baseline.detect(sample);
        scores.push((stat_result.anomaly_score, self.weights.1));
        all_contributions.extend(stat_result.contributing_features);

        // Time Series (use first feature as value)
        if let Some(&value) = sample.features.first() {
            let ts_result = self
                .time_series
                .detect(&sample.entity_id, sample.timestamp, value);
            scores.push((ts_result.anomaly_score, self.weights.2));
            all_contributions.extend(ts_result.contributing_features);
        }

        // Weighted average
        let total_weight: f64 = scores.iter().map(|(_, w)| w).sum();
        let ensemble_score: f64 = scores.iter().map(|(s, w)| s * w).sum::<f64>() / total_weight;

        let mut result = AnomalyResult::new(
            &sample.entity_id,
            sample.timestamp,
            ensemble_score,
            0.5,
            ModelType::Ensemble,
        );
        result.contributing_features = all_contributions;
        result
    }
}

impl Default for EnsembleDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Security event feature extractor
pub struct SecurityFeatureExtractor;

impl SecurityFeatureExtractor {
    /// Extract features from process execution event
    pub fn process_exec_features(
        entity_id: &str,
        timestamp: i64,
        pid: i64,
        ppid: i64,
        uid: u32,
        argc: usize,
        exe_path_len: usize,
        is_root: bool,
        from_tmp: bool,
    ) -> FeatureVector {
        let mut fv = FeatureVector::new(entity_id, timestamp);
        fv.add_feature("pid", pid as f64);
        fv.add_feature("ppid", ppid as f64);
        fv.add_feature("uid", uid as f64);
        fv.add_feature("argc", argc as f64);
        fv.add_feature("exe_path_len", exe_path_len as f64);
        fv.add_feature("is_root", if is_root { 1.0 } else { 0.0 });
        fv.add_feature("from_tmp", if from_tmp { 1.0 } else { 0.0 });
        fv
    }

    /// Extract features from network connection event
    pub fn network_conn_features(
        entity_id: &str,
        timestamp: i64,
        src_port: u16,
        dst_port: u16,
        bytes_sent: u64,
        bytes_recv: u64,
        duration_ms: u64,
        is_outbound: bool,
    ) -> FeatureVector {
        let mut fv = FeatureVector::new(entity_id, timestamp);
        fv.add_feature("src_port", src_port as f64);
        fv.add_feature("dst_port", dst_port as f64);
        fv.add_feature("bytes_sent", bytes_sent as f64);
        fv.add_feature("bytes_recv", bytes_recv as f64);
        fv.add_feature("duration_ms", duration_ms as f64);
        fv.add_feature("is_outbound", if is_outbound { 1.0 } else { 0.0 });
        fv.add_feature(
            "bytes_ratio",
            if bytes_recv > 0 {
                bytes_sent as f64 / bytes_recv as f64
            } else {
                bytes_sent as f64
            },
        );
        fv
    }

    /// Extract features from file access event
    pub fn file_access_features(
        entity_id: &str,
        timestamp: i64,
        path_depth: usize,
        is_sensitive_path: bool,
        is_write: bool,
        is_exec: bool,
        file_size: u64,
    ) -> FeatureVector {
        let mut fv = FeatureVector::new(entity_id, timestamp);
        fv.add_feature("path_depth", path_depth as f64);
        fv.add_feature("is_sensitive", if is_sensitive_path { 1.0 } else { 0.0 });
        fv.add_feature("is_write", if is_write { 1.0 } else { 0.0 });
        fv.add_feature("is_exec", if is_exec { 1.0 } else { 0.0 });
        fv.add_feature("file_size", file_size as f64);
        fv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_data(n: usize) -> Vec<FeatureVector> {
        (0..n)
            .map(|i| {
                let mut fv = FeatureVector::new(&format!("entity-{i}"), i as i64 * 1000);
                fv.add_feature("f1", (i as f64).sin() * 10.0 + 50.0);
                fv.add_feature("f2", (i as f64).cos() * 5.0 + 25.0);
                fv.add_feature("f3", i as f64 % 10.0);
                fv
            })
            .collect()
    }

    #[test]
    fn test_isolation_forest() {
        let data = make_test_data(500);
        let mut forest = IsolationForest::new(100, 256);

        forest.fit(&data).unwrap();
        assert!(forest.is_trained());

        // Normal sample
        let normal = &data[100];
        let score = forest.score(normal).unwrap();
        assert!(score < 0.6);

        // Anomalous sample
        let mut anomaly = FeatureVector::new("anomaly", 0);
        anomaly.add_feature("f1", 1000.0);
        anomaly.add_feature("f2", -500.0);
        anomaly.add_feature("f3", 999.0);
        let score = forest.score(&anomaly).unwrap();
        assert!(score > 0.5);
    }

    #[test]
    fn test_statistical_baseline() {
        let mut baseline = StatisticalBaseline::new(3.0);

        // Train on normal data
        for i in 0..100 {
            let mut fv = FeatureVector::new("entity", i * 1000);
            fv.add_feature("value", 50.0 + (i as f64 % 10.0));
            baseline.update(&fv);
        }

        // Normal sample
        let mut normal = FeatureVector::new("entity", 100000);
        normal.add_feature("value", 55.0);
        let result = baseline.detect(&normal);
        assert!(!result.is_anomaly);

        // Anomalous sample
        let mut anomaly = FeatureVector::new("entity", 100000);
        anomaly.add_feature("value", 500.0);
        let result = baseline.detect(&anomaly);
        assert!(result.is_anomaly);
    }

    #[test]
    fn test_time_series_detector() {
        let mut detector = TimeSeriesDetector::new(50, 3.0);

        // Feed normal values
        for i in 0..100 {
            let value = 50.0 + (i as f64 % 10.0);
            let result = detector.detect("entity", i * 1000, value);
            if i > 10 {
                assert!(!result.is_anomaly);
            }
        }

        // Anomalous value
        let result = detector.detect("entity", 100000, 500.0);
        assert!(result.is_anomaly);
    }

    #[test]
    fn test_ensemble_detector() {
        let data = make_test_data(500);
        let mut detector = EnsembleDetector::new();

        // Train
        detector.train_isolation_forest(&data).unwrap();
        for sample in &data {
            detector.update_baseline(sample);
        }

        // Normal sample
        let result = detector.detect(&data[100]);
        assert!(!result.is_anomaly);

        // Anomalous sample
        let mut anomaly = FeatureVector::new("anomaly", 0);
        anomaly.add_feature("f1", 1000.0);
        anomaly.add_feature("f2", -500.0);
        anomaly.add_feature("f3", 999.0);
        let result = detector.detect(&anomaly);
        assert!(result.is_anomaly);
    }

    #[test]
    fn test_feature_extractor() {
        let fv = SecurityFeatureExtractor::process_exec_features(
            "proc-1", 1000, 1234, 1, 0, 5, 20, true, false,
        );

        assert_eq!(fv.dimension(), 7);
        assert_eq!(fv.features[5], 1.0); // is_root
    }
}
