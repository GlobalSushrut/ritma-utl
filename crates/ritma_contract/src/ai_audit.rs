//! AI and Automation Decision Audit Trail
//!
//! Capability #7: Track AI/automation decisions with:
//! - Model versioning and identification
//! - Input hashing for reproducibility
//! - Explanation payloads
//! - Decision lineage

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ============================================================================
// Model Identity
// ============================================================================

/// AI/ML model identity and versioning
#[derive(Debug, Clone)]
pub struct ModelIdentity {
    /// Model name
    pub name: String,
    /// Model version
    pub version: String,
    /// Model hash (weights/parameters hash)
    pub model_hash: [u8; 32],
    /// Training data hash
    pub training_hash: Option<[u8; 32]>,
    /// Framework (e.g., "pytorch", "tensorflow", "sklearn")
    pub framework: String,
    /// Framework version
    pub framework_version: String,
    /// Model type
    pub model_type: ModelType,
    /// Metadata
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelType {
    /// Classification model
    Classification,
    /// Regression model
    Regression,
    /// Anomaly detection
    AnomalyDetection,
    /// Natural language processing
    Nlp,
    /// Computer vision
    Vision,
    /// Reinforcement learning
    ReinforcementLearning,
    /// Rule-based system
    RuleBased,
    /// Ensemble
    Ensemble,
    /// Other
    Other,
}

impl ModelType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Classification => "classification",
            Self::Regression => "regression",
            Self::AnomalyDetection => "anomaly_detection",
            Self::Nlp => "nlp",
            Self::Vision => "vision",
            Self::ReinforcementLearning => "reinforcement_learning",
            Self::RuleBased => "rule_based",
            Self::Ensemble => "ensemble",
            Self::Other => "other",
        }
    }
}

impl ModelIdentity {
    pub fn new(name: &str, version: &str, model_hash: [u8; 32]) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            model_hash,
            training_hash: None,
            framework: "unknown".to_string(),
            framework_version: "unknown".to_string(),
            model_type: ModelType::Other,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_framework(mut self, framework: &str, version: &str) -> Self {
        self.framework = framework.to_string();
        self.framework_version = version.to_string();
        self
    }

    pub fn with_model_type(mut self, model_type: ModelType) -> Self {
        self.model_type = model_type;
        self
    }

    /// Generate a unique model ID
    pub fn model_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"model-id@0.1");
        h.update(self.name.as_bytes());
        h.update(self.version.as_bytes());
        h.update(&self.model_hash);
        format!("model-{}", hex::encode(&h.finalize()[..12]))
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "model-identity@0.1",
            &self.name,
            &self.version,
            hex::encode(self.model_hash),
            self.training_hash.map(hex::encode),
            &self.framework,
            &self.framework_version,
            self.model_type.as_str(),
            &self.metadata,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Decision Input
// ============================================================================

/// Input to an AI/automation decision
#[derive(Debug, Clone)]
pub struct DecisionInput {
    /// Input ID
    pub input_id: String,
    /// Input hash (for reproducibility)
    pub input_hash: [u8; 32],
    /// Input type
    pub input_type: InputType,
    /// Feature names (if applicable)
    pub feature_names: Vec<String>,
    /// Feature values hash
    pub features_hash: Option<[u8; 32]>,
    /// Raw input size in bytes
    pub input_size: u64,
    /// Timestamp
    pub timestamp: String,
    /// Source reference
    pub source_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputType {
    /// Structured features
    Features,
    /// Text input
    Text,
    /// Image input
    Image,
    /// Time series
    TimeSeries,
    /// Graph/network
    Graph,
    /// Raw bytes
    Raw,
}

impl InputType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Features => "features",
            Self::Text => "text",
            Self::Image => "image",
            Self::TimeSeries => "time_series",
            Self::Graph => "graph",
            Self::Raw => "raw",
        }
    }
}

impl DecisionInput {
    pub fn from_bytes(data: &[u8], input_type: InputType) -> Self {
        let mut h = Sha256::new();
        h.update(data);
        let input_hash: [u8; 32] = h.finalize().into();

        let input_id = {
            let mut h = Sha256::new();
            h.update(b"input-id@0.1");
            h.update(&input_hash);
            format!("inp-{}", hex::encode(&h.finalize()[..12]))
        };

        Self {
            input_id,
            input_hash,
            input_type,
            feature_names: Vec::new(),
            features_hash: None,
            input_size: data.len() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_ref: None,
        }
    }

    pub fn with_features(mut self, names: Vec<String>, values_hash: [u8; 32]) -> Self {
        self.feature_names = names;
        self.features_hash = Some(values_hash);
        self
    }

    pub fn with_source(mut self, source: &str) -> Self {
        self.source_ref = Some(source.to_string());
        self
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "decision-input@0.1",
            &self.input_id,
            hex::encode(self.input_hash),
            self.input_type.as_str(),
            &self.feature_names,
            self.features_hash.map(hex::encode),
            self.input_size,
            &self.timestamp,
            &self.source_ref,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Decision Output
// ============================================================================

/// Output of an AI/automation decision
#[derive(Debug, Clone)]
pub struct DecisionOutput {
    /// Output ID
    pub output_id: String,
    /// Decision type
    pub decision_type: DecisionType,
    /// Primary result
    pub result: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: Option<f64>,
    /// Probability distribution (class -> probability)
    pub probabilities: Option<BTreeMap<String, f64>>,
    /// Threshold used
    pub threshold: Option<f64>,
    /// Output hash
    pub output_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionType {
    /// Binary classification
    Binary,
    /// Multi-class classification
    MultiClass,
    /// Numeric prediction
    Numeric,
    /// Ranking/ordering
    Ranking,
    /// Recommendation
    Recommendation,
    /// Action selection
    Action,
    /// Alert/trigger
    Alert,
}

impl DecisionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::MultiClass => "multi_class",
            Self::Numeric => "numeric",
            Self::Ranking => "ranking",
            Self::Recommendation => "recommendation",
            Self::Action => "action",
            Self::Alert => "alert",
        }
    }
}

impl DecisionOutput {
    pub fn new(decision_type: DecisionType, result: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"output@0.1");
        h.update(result.as_bytes());
        let output_hash: [u8; 32] = h.finalize().into();

        let output_id = format!("out-{}", hex::encode(&output_hash[..12]));

        Self {
            output_id,
            decision_type,
            result: result.to_string(),
            confidence: None,
            probabilities: None,
            threshold: None,
            output_hash,
        }
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = Some(confidence.clamp(0.0, 1.0));
        self
    }

    pub fn with_probabilities(mut self, probs: BTreeMap<String, f64>) -> Self {
        self.probabilities = Some(probs);
        self
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "decision-output@0.1",
            &self.output_id,
            self.decision_type.as_str(),
            &self.result,
            self.confidence,
            &self.probabilities,
            self.threshold,
            hex::encode(self.output_hash),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Explanation
// ============================================================================

/// Explanation for an AI decision
#[derive(Debug, Clone)]
pub struct DecisionExplanation {
    /// Explanation type
    pub explanation_type: ExplanationType,
    /// Human-readable summary
    pub summary: String,
    /// Feature importances (feature -> importance)
    pub feature_importances: Option<BTreeMap<String, f64>>,
    /// Counterfactuals
    pub counterfactuals: Vec<String>,
    /// Decision rules (if rule-based)
    pub rules: Vec<String>,
    /// Attention weights (for transformers)
    pub attention: Option<Vec<f64>>,
    /// SHAP values hash
    pub shap_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplanationType {
    /// Feature importance based
    FeatureImportance,
    /// SHAP values
    Shap,
    /// LIME
    Lime,
    /// Attention-based
    Attention,
    /// Rule-based
    RuleBased,
    /// Counterfactual
    Counterfactual,
    /// Natural language
    NaturalLanguage,
    /// None available
    None,
}

impl ExplanationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FeatureImportance => "feature_importance",
            Self::Shap => "shap",
            Self::Lime => "lime",
            Self::Attention => "attention",
            Self::RuleBased => "rule_based",
            Self::Counterfactual => "counterfactual",
            Self::NaturalLanguage => "natural_language",
            Self::None => "none",
        }
    }
}

impl DecisionExplanation {
    pub fn new(explanation_type: ExplanationType, summary: &str) -> Self {
        Self {
            explanation_type,
            summary: summary.to_string(),
            feature_importances: None,
            counterfactuals: Vec::new(),
            rules: Vec::new(),
            attention: None,
            shap_hash: None,
        }
    }

    pub fn with_feature_importances(mut self, importances: BTreeMap<String, f64>) -> Self {
        self.feature_importances = Some(importances);
        self
    }

    pub fn add_counterfactual(&mut self, cf: String) {
        self.counterfactuals.push(cf);
    }

    pub fn add_rule(&mut self, rule: String) {
        self.rules.push(rule);
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "decision-explanation@0.1",
            self.explanation_type.as_str(),
            &self.summary,
            &self.feature_importances,
            &self.counterfactuals,
            &self.rules,
            self.shap_hash.map(hex::encode),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Decision Record
// ============================================================================

/// Complete AI decision audit record
#[derive(Debug, Clone)]
pub struct AiDecisionRecord {
    /// Decision ID
    pub decision_id: String,
    /// Timestamp
    pub timestamp: String,
    /// Model identity
    pub model: ModelIdentity,
    /// Input
    pub input: DecisionInput,
    /// Output
    pub output: DecisionOutput,
    /// Explanation
    pub explanation: Option<DecisionExplanation>,
    /// Latency in milliseconds
    pub latency_ms: Option<u64>,
    /// Node ID where decision was made
    pub node_id: String,
    /// Request ID (for tracing)
    pub request_id: Option<String>,
    /// Parent decision ID (for chained decisions)
    pub parent_decision_id: Option<String>,
    /// Human override (if decision was overridden)
    pub human_override: Option<HumanOverride>,
}

#[derive(Debug, Clone)]
pub struct HumanOverride {
    /// Override timestamp
    pub timestamp: String,
    /// User who overrode
    pub user_id: String,
    /// Original decision
    pub original_result: String,
    /// Overridden result
    pub override_result: String,
    /// Reason for override
    pub reason: String,
}

impl AiDecisionRecord {
    pub fn new(
        model: ModelIdentity,
        input: DecisionInput,
        output: DecisionOutput,
        node_id: &str,
    ) -> Self {
        let now = chrono::Utc::now();
        let decision_id = {
            let mut h = Sha256::new();
            h.update(b"ai-decision@0.1");
            h.update(model.model_id().as_bytes());
            h.update(&input.input_hash);
            h.update(&output.output_hash);
            h.update(now.to_rfc3339().as_bytes());
            format!("dec-{}", hex::encode(&h.finalize()[..16]))
        };

        Self {
            decision_id,
            timestamp: now.to_rfc3339(),
            model,
            input,
            output,
            explanation: None,
            latency_ms: None,
            node_id: node_id.to_string(),
            request_id: None,
            parent_decision_id: None,
            human_override: None,
        }
    }

    pub fn with_explanation(mut self, explanation: DecisionExplanation) -> Self {
        self.explanation = Some(explanation);
        self
    }

    pub fn with_latency(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    pub fn with_request_id(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.to_string());
        self
    }

    pub fn with_parent(mut self, parent_id: &str) -> Self {
        self.parent_decision_id = Some(parent_id.to_string());
        self
    }

    /// Record a human override
    pub fn record_override(&mut self, user_id: &str, new_result: &str, reason: &str) {
        self.human_override = Some(HumanOverride {
            timestamp: chrono::Utc::now().to_rfc3339(),
            user_id: user_id.to_string(),
            original_result: self.output.result.clone(),
            override_result: new_result.to_string(),
            reason: reason.to_string(),
        });
    }

    /// Compute record hash for integrity
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"record-hash@0.1");
        h.update(self.decision_id.as_bytes());
        h.update(&self.model.model_hash);
        h.update(&self.input.input_hash);
        h.update(&self.output.output_hash);
        h.finalize().into()
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        // Use nested tuples to avoid exceeding ciborium's tuple size limit
        let core = (
            "ai-decision-record@0.1",
            &self.decision_id,
            &self.timestamp,
            self.model.model_id(),
            hex::encode(self.model.model_hash),
        );
        let io = (
            &self.input.input_id,
            hex::encode(self.input.input_hash),
            &self.output.output_id,
            &self.output.result,
            self.output.confidence,
        );
        let meta = (
            self.explanation
                .as_ref()
                .map(|e| e.explanation_type.as_str()),
            self.latency_ms,
            &self.node_id,
            &self.request_id,
            &self.parent_decision_id,
            self.human_override.is_some(),
            hex::encode(self.record_hash()),
        );

        let tuple = (core, io, meta);
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Decision Audit Log
// ============================================================================

/// Audit log for AI decisions
#[derive(Debug)]
pub struct AiAuditLog {
    /// Node ID
    pub node_id: String,
    /// Records
    records: Vec<AiDecisionRecord>,
    /// Model registry (model_id -> ModelIdentity)
    models: BTreeMap<String, ModelIdentity>,
}

impl AiAuditLog {
    pub fn new(node_id: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            records: Vec::new(),
            models: BTreeMap::new(),
        }
    }

    /// Register a model
    pub fn register_model(&mut self, model: ModelIdentity) {
        self.models.insert(model.model_id(), model);
    }

    /// Log a decision
    pub fn log_decision(&mut self, record: AiDecisionRecord) {
        // Auto-register model if not present
        if !self.models.contains_key(&record.model.model_id()) {
            self.models
                .insert(record.model.model_id(), record.model.clone());
        }
        self.records.push(record);
    }

    /// Get decisions by model
    pub fn decisions_by_model(&self, model_id: &str) -> Vec<&AiDecisionRecord> {
        self.records
            .iter()
            .filter(|r| r.model.model_id() == model_id)
            .collect()
    }

    /// Get decisions in time range
    pub fn decisions_in_range(&self, start: &str, end: &str) -> Vec<&AiDecisionRecord> {
        self.records
            .iter()
            .filter(|r| r.timestamp >= start.to_string() && r.timestamp <= end.to_string())
            .collect()
    }

    /// Get overridden decisions
    pub fn overridden_decisions(&self) -> Vec<&AiDecisionRecord> {
        self.records
            .iter()
            .filter(|r| r.human_override.is_some())
            .collect()
    }

    /// Get decision chain (follow parent_decision_id)
    pub fn decision_chain(&self, decision_id: &str) -> Vec<&AiDecisionRecord> {
        let mut chain = Vec::new();
        let mut current_id = Some(decision_id.to_string());

        while let Some(id) = current_id {
            if let Some(record) = self.records.iter().find(|r| r.decision_id == id) {
                chain.push(record);
                current_id = record.parent_decision_id.clone();
            } else {
                break;
            }
        }

        chain.reverse();
        chain
    }

    /// Total records
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Is empty
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let records: Vec<_> = self
            .records
            .iter()
            .map(|r| {
                (
                    &r.decision_id,
                    &r.timestamp,
                    r.model.model_id(),
                    &r.output.result,
                )
            })
            .collect();

        let models: Vec<_> = self
            .models
            .values()
            .map(|m| (m.model_id(), &m.name, &m.version))
            .collect();

        let tuple = (
            "ai-audit-log@0.1",
            &self.node_id,
            records.len(),
            models,
            records,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_identity() {
        let model = ModelIdentity::new("anomaly_detector", "1.0.0", [0xaa; 32])
            .with_framework("sklearn", "1.2.0")
            .with_model_type(ModelType::AnomalyDetection);

        assert!(!model.model_id().is_empty());
        assert!(model.model_id().starts_with("model-"));

        let cbor = model.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_decision_input() {
        let input = DecisionInput::from_bytes(b"test input data", InputType::Features)
            .with_source("trace-event-123");

        assert!(!input.input_id.is_empty());
        assert_eq!(input.input_size, 15);

        let cbor = input.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_decision_output() {
        let mut probs = BTreeMap::new();
        probs.insert("normal".to_string(), 0.3);
        probs.insert("anomaly".to_string(), 0.7);

        let output = DecisionOutput::new(DecisionType::Binary, "anomaly")
            .with_confidence(0.7)
            .with_probabilities(probs)
            .with_threshold(0.5);

        assert!(!output.output_id.is_empty());
        assert_eq!(output.confidence, Some(0.7));

        let cbor = output.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_decision_explanation() {
        let mut importances = BTreeMap::new();
        importances.insert("feature_a".to_string(), 0.5);
        importances.insert("feature_b".to_string(), 0.3);

        let mut explanation = DecisionExplanation::new(
            ExplanationType::FeatureImportance,
            "High anomaly score due to unusual network activity",
        )
        .with_feature_importances(importances);

        explanation
            .add_counterfactual("If network_bytes < 1000, prediction would be normal".to_string());

        let cbor = explanation.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_ai_decision_record() {
        let model = ModelIdentity::new("test_model", "1.0", [0xbb; 32]);
        let input = DecisionInput::from_bytes(b"input", InputType::Features);
        let output = DecisionOutput::new(DecisionType::Binary, "positive");

        let mut record = AiDecisionRecord::new(model, input, output, "node1")
            .with_latency(50)
            .with_request_id("req-123");

        assert!(!record.decision_id.is_empty());
        assert_ne!(record.record_hash(), [0u8; 32]);

        // Test override
        record.record_override("admin", "negative", "False positive");
        assert!(record.human_override.is_some());

        let cbor = record.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_ai_audit_log() {
        let mut log = AiAuditLog::new("node1");

        let model = ModelIdentity::new("model1", "1.0", [0xcc; 32]);
        log.register_model(model.clone());

        let input = DecisionInput::from_bytes(b"test", InputType::Features);
        let output = DecisionOutput::new(DecisionType::Binary, "yes");
        let record = AiDecisionRecord::new(model, input, output, "node1");

        log.log_decision(record);

        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());

        let cbor = log.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_decision_chain() {
        let mut log = AiAuditLog::new("node1");

        let model = ModelIdentity::new("model1", "1.0", [0xdd; 32]);

        // First decision
        let input1 = DecisionInput::from_bytes(b"input1", InputType::Features);
        let output1 = DecisionOutput::new(DecisionType::Binary, "step1");
        let record1 = AiDecisionRecord::new(model.clone(), input1, output1, "node1");
        let id1 = record1.decision_id.clone();
        log.log_decision(record1);

        // Second decision (child of first)
        let input2 = DecisionInput::from_bytes(b"input2", InputType::Features);
        let output2 = DecisionOutput::new(DecisionType::Binary, "step2");
        let record2 =
            AiDecisionRecord::new(model.clone(), input2, output2, "node1").with_parent(&id1);
        let id2 = record2.decision_id.clone();
        log.log_decision(record2);

        let chain = log.decision_chain(&id2);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].decision_id, id1);
        assert_eq!(chain[1].decision_id, id2);
    }
}
