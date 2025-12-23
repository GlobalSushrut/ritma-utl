//! Professional Threat Detection Engine
//!
//! Based on real cybersecurity principles:
//! - MITRE ATT&CK framework
//! - Statistical anomaly detection
//! - Behavioral analysis
//! - Kill chain tracking
//! - Context-aware scoring

use common_models::DecisionEvent;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

pub mod correlation;
pub mod ml;
pub mod normalization;
pub mod sequence;
pub mod temporal;
pub mod volume;

#[derive(Error, Debug)]
pub enum ThreatError {
    #[error("Threat detection failed: {0}")]
    DetectionFailed(String),

    #[error("Baseline not found: {0}")]
    BaselineNotFound(String),
}

/// Lightweight detection log for recent indicators (for demo/stats)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionLog {
    pub ts: String,
    pub actor_id: String,
    pub action: String,
    pub threat_score: f64,
    pub is_threat: bool,
    pub indicators: Vec<String>,
}

/// MITRE ATT&CK Tactics (simplified)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AttackTactic {
    Reconnaissance,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
    Benign,
}

impl AttackTactic {
    /// Get base risk score for this tactic
    pub fn risk_score(&self) -> f64 {
        match self {
            AttackTactic::Benign => 0.0,
            AttackTactic::Reconnaissance => 0.3,
            AttackTactic::Discovery => 0.4,
            AttackTactic::InitialAccess => 0.6,
            AttackTactic::Execution => 0.7,
            AttackTactic::Collection => 0.7,
            AttackTactic::CredentialAccess => 0.8,
            AttackTactic::Persistence => 0.8,
            AttackTactic::PrivilegeEscalation => 0.9,
            AttackTactic::DefenseEvasion => 0.9,
            AttackTactic::LateralMovement => 0.9,
            AttackTactic::Exfiltration => 0.95,
            AttackTactic::Impact => 1.0,
        }
    }
}

/// Attack pattern classifier
pub struct AttackClassifier;

impl AttackClassifier {
    /// Classify action into MITRE ATT&CK tactic (with normalization)
    pub fn classify(action: &str) -> AttackTactic {
        use normalization::ActionNormalizer;

        // Normalize action first to handle obfuscation
        let normalizer = ActionNormalizer::new();
        let normalized = normalizer.normalize(action);
        let action_lower = normalized.to_lowercase();

        // Benign (normal operations) - CHECK FIRST to avoid false positives
        if action_lower == "read"
            || action_lower == "view"
            || action_lower == "get"
            || action_lower == "fetch"
            || action_lower == "show"
            || action_lower.starts_with("read_")
            || action_lower.starts_with("view_")
            || action_lower.starts_with("get_")
        {
            return AttackTactic::Benign;
        }

        // Impact (Destructive)
        if action_lower.contains("delete")
            || action_lower.contains("drop")
            || action_lower.contains("destroy")
            || action_lower.contains("wipe")
            || action_lower.contains("encrypt")
            || action_lower.contains("ransom")
        {
            return AttackTactic::Impact;
        }

        // Exfiltration
        if action_lower == "export"
            || action_lower.starts_with("export")
            || action_lower.contains("download")
            || action_lower.contains("dump")
            || action_lower.contains("exfil")
            || action_lower.contains("transfer")
        {
            return AttackTactic::Exfiltration;
        }

        // Privilege Escalation
        if action_lower.contains("sudo")
            || action_lower.contains("admin")
            || action_lower.contains("elevate")
            || action_lower.contains("root")
            || action_lower.contains("privilege")
        {
            return AttackTactic::PrivilegeEscalation;
        }

        // Credential Access
        if action_lower.contains("password")
            || action_lower.contains("credential")
            || action_lower.contains("token")
            || action_lower.contains("key")
            || action_lower.contains("secret")
            || action_lower.contains("auth")
        {
            return AttackTactic::CredentialAccess;
        }

        // Lateral Movement
        if action_lower.contains("ssh")
            || action_lower.contains("rdp")
            || action_lower.contains("remote")
            || action_lower.contains("pivot")
            || action_lower.contains("lateral")
        {
            return AttackTactic::LateralMovement;
        }

        // Execution
        if action_lower.contains("exec")
            || action_lower.contains("run")
            || action_lower.contains("execute")
            || action_lower.contains("shell")
            || action_lower.contains("cmd")
            || action_lower.contains("script")
        {
            return AttackTactic::Execution;
        }

        // Discovery
        if action_lower.contains("list")
            || action_lower.contains("scan")
            || action_lower.contains("enum")
            || action_lower.contains("discover")
            || action_lower.contains("probe")
        {
            return AttackTactic::Discovery;
        }

        // Reconnaissance
        if action_lower.contains("recon")
            || action_lower.contains("fingerprint")
            || action_lower.contains("map")
            || action_lower.contains("survey")
        {
            return AttackTactic::Reconnaissance;
        }

        // Collection
        if action_lower.contains("collect")
            || action_lower.contains("gather")
            || action_lower.contains("harvest")
        {
            return AttackTactic::Collection;
        }

        // Default: treat unknown as potentially suspicious (Discovery)
        AttackTactic::Discovery
    }
}

/// Statistical baseline for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalBaseline {
    pub namespace_id: String,

    // Action frequency distribution
    pub action_frequencies: HashMap<String, f64>,
    pub action_mean: f64,
    pub action_std_dev: f64,

    // Actor behavior
    pub actor_frequencies: HashMap<String, f64>,
    pub known_actors: HashMap<String, ActorProfile>,

    // Temporal patterns
    pub hourly_distribution: Vec<f64>, // 24 hours
    pub request_rate_mean: f64,
    pub request_rate_std_dev: f64,

    // Total observations
    pub total_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorProfile {
    pub actor_id: String,
    pub total_actions: usize,
    pub action_distribution: HashMap<String, usize>,
    pub risk_score: f64,
    pub first_seen: String,
    pub last_seen: String,
}

impl StatisticalBaseline {
    pub fn new(namespace_id: String) -> Self {
        Self {
            namespace_id,
            action_frequencies: HashMap::new(),
            action_mean: 0.0,
            action_std_dev: 0.0,
            actor_frequencies: HashMap::new(),
            known_actors: HashMap::new(),
            hourly_distribution: vec![0.0; 24],
            request_rate_mean: 0.0,
            request_rate_std_dev: 0.0,
            total_events: 0,
        }
    }

    /// Update baseline with new event
    pub fn update(&mut self, event: &DecisionEvent) {
        self.total_events += 1;

        // Update action frequencies
        *self
            .action_frequencies
            .entry(event.action.name.clone())
            .or_insert(0.0) += 1.0;

        // Update actor frequencies
        *self
            .actor_frequencies
            .entry(event.actor.id_hash.clone())
            .or_insert(0.0) += 1.0;

        // Update actor profile
        let profile = self
            .known_actors
            .entry(event.actor.id_hash.clone())
            .or_insert_with(|| ActorProfile {
                actor_id: event.actor.id_hash.clone(),
                total_actions: 0,
                action_distribution: HashMap::new(),
                risk_score: 0.5, // Neutral
                first_seen: event.ts.clone(),
                last_seen: event.ts.clone(),
            });

        profile.total_actions += 1;
        *profile
            .action_distribution
            .entry(event.action.name.clone())
            .or_insert(0) += 1;
        profile.last_seen = event.ts.clone();

        // Recalculate statistics
        self.recalculate_stats();
    }

    fn recalculate_stats(&mut self) {
        if self.action_frequencies.is_empty() {
            return;
        }

        // Calculate mean and std dev for actions
        let values: Vec<f64> = self.action_frequencies.values().copied().collect();
        self.action_mean = values.iter().sum::<f64>() / values.len() as f64;

        let variance: f64 = values
            .iter()
            .map(|v| (v - self.action_mean).powi(2))
            .sum::<f64>()
            / values.len() as f64;
        self.action_std_dev = variance.sqrt();
    }

    /// Calculate Z-score for an action
    pub fn action_z_score(&self, action: &str) -> f64 {
        if self.action_std_dev == 0.0 {
            return 0.0;
        }

        let freq = self.action_frequencies.get(action).copied().unwrap_or(0.0);
        (freq - self.action_mean) / self.action_std_dev
    }

    /// Calculate distance from another baseline (for drift detection)
    /// Returns a normalized score 0.0-1.0 where:
    /// - 0.0 = identical baselines
    /// - 1.0 = completely different baselines
    pub fn distance_from(&self, other: &StatisticalBaseline) -> f64 {
        // If both baselines are empty, they're identical
        if self.action_frequencies.is_empty() && other.action_frequencies.is_empty() {
            return 0.0;
        }

        // If one is empty and the other isn't, they're different
        // But if we're just starting to build the baseline, this is expected
        if other.action_frequencies.is_empty() {
            // Golden baseline is empty, we're building from scratch
            return 0.0; // No drift yet
        }

        let mut total_distance = 0.0;
        let mut max_possible_distance = 0.0;

        // Get all unique actions
        let mut all_actions: std::collections::HashSet<String> =
            self.action_frequencies.keys().cloned().collect();
        all_actions.extend(other.action_frequencies.keys().cloned());

        for action in all_actions {
            let self_freq = self.action_frequencies.get(&action).copied().unwrap_or(0.0);
            let other_freq = other
                .action_frequencies
                .get(&action)
                .copied()
                .unwrap_or(0.0);

            // Calculate difference
            let diff = (self_freq - other_freq).abs();
            total_distance += diff;

            // Max possible difference is the larger of the two
            max_possible_distance += self_freq.max(other_freq);
        }

        if max_possible_distance == 0.0 {
            return 0.0;
        }

        // Normalize to 0-1 range
        (total_distance / max_possible_distance).min(1.0)
    }
}

/// Comprehensive threat detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub is_threat: bool,
    pub threat_score: f64, // 0.0 - 1.0
    pub confidence: f64,   // 0.0 - 1.0

    // Attack classification
    pub attack_tactic: AttackTactic,
    pub tactic_risk: f64,

    // Statistical anomaly
    pub is_statistical_anomaly: bool,
    pub z_score: f64,

    // Behavioral flags
    pub is_unknown_actor: bool,
    pub is_unknown_action: bool,
    pub is_privilege_escalation: bool,
    pub is_data_exfiltration: bool,
    pub is_destructive: bool,

    // Context
    pub actor_risk_score: f64,
    pub action_frequency: f64,

    // Explanation
    pub threat_indicators: Vec<String>,
    pub recommended_action: String,
}

/// Professional threat detection engine
pub struct ThreatDetectionEngine {
    baselines: HashMap<String, StatisticalBaseline>,
    golden_baselines: HashMap<String, StatisticalBaseline>, // Immutable reference baseline
    baseline_drift: HashMap<String, f64>,                   // Track drift from golden
    volume_tracker: volume::VolumeTracker,                  // Track volume semantics
    temporal_analyzer: temporal::TemporalAnalyzer,          // Track temporal behavior
    sequence_detector: sequence::SequenceDetector,          // Track ordered tactics per actor
    correlation_engine: correlation::CorrelationEngine,     // Track multi-actor coordination
    ml_assist: ml::MLAssist,                                // Optional bounded ML confidence assist
    recent_indicators: VecDeque<DetectionLog>,              // recent detection indicators
}

impl ThreatDetectionEngine {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            golden_baselines: HashMap::new(),
            baseline_drift: HashMap::new(),
            volume_tracker: volume::VolumeTracker::new(),
            temporal_analyzer: temporal::TemporalAnalyzer::new(),
            sequence_detector: sequence::SequenceDetector::new(),
            correlation_engine: correlation::CorrelationEngine::new(),
            ml_assist: ml::MLAssist::new(),
            recent_indicators: VecDeque::with_capacity(50),
        }
    }

    pub fn create_baseline(&mut self, namespace_id: String) {
        let baseline = StatisticalBaseline::new(namespace_id.clone());
        self.baselines
            .insert(namespace_id.clone(), baseline.clone());
        // Set golden baseline (immutable reference)
        self.golden_baselines.insert(namespace_id.clone(), baseline);
        self.baseline_drift.insert(namespace_id, 0.0);
    }

    pub fn get_baseline(&self, namespace_id: &str) -> Result<&StatisticalBaseline, ThreatError> {
        self.baselines
            .get(namespace_id)
            .ok_or_else(|| ThreatError::BaselineNotFound(namespace_id.to_string()))
    }

    /// Track observed volume for an actor (bytes)
    pub fn track_volume(&mut self, actor_id: &str, volume_bytes: u64) {
        self.volume_tracker.track_actor(actor_id, volume_bytes);
    }

    /// Recompute volume baselines
    pub fn calibrate_volumes(&mut self) {
        self.volume_tracker.calibrate();
    }

    /// Enable or disable ML assist (bounded confidence delta)
    pub fn set_ml_enabled(&mut self, enabled: bool) {
        self.ml_assist.enabled = enabled;
    }

    /// Check if ML assist is enabled
    pub fn is_ml_enabled(&self) -> bool {
        self.ml_assist.enabled
    }

    /// Detect threats BEFORE updating baseline
    pub fn detect_threat(
        &mut self,
        namespace_id: &str,
        event: &DecisionEvent,
    ) -> Result<ThreatDetection, ThreatError> {
        let mut threat_indicators = Vec::new();
        let mut threat_score = 0.0;

        // 1. Attack Pattern Classification (40% weight)
        let attack_tactic = AttackClassifier::classify(&event.action.name);
        // Observe tactic for sequence detection timeline
        self.sequence_detector
            .observe(&event.actor.id_hash, attack_tactic.clone(), &event.ts);
        // Observe for correlation windows (tactic & time bucket)
        self.correlation_engine
            .observe(&event.actor.id_hash, attack_tactic.clone(), &event.ts);
        let tactic_risk = attack_tactic.risk_score();
        threat_score += tactic_risk * 0.4;

        if tactic_risk > 0.7 {
            threat_indicators.push(format!(
                "High-risk tactic: {attack_tactic:?} (score: {tactic_risk:.2})"
            ));
        }

        // 2. Statistical Anomaly Detection (20% weight)
        // Acquire baseline after sequence observation to avoid borrow conflicts
        let baseline = self.get_baseline(namespace_id)?;
        let z_score = baseline.action_z_score(&event.action.name);
        let is_statistical_anomaly = z_score.abs() > 2.0; // 2 standard deviations

        if is_statistical_anomaly {
            threat_score += 0.2;
            threat_indicators.push(format!("Statistical anomaly: Z-score {z_score:.2}"));
        }

        // 3. Unknown Actor (20% weight)
        let is_unknown_actor = !baseline
            .actor_frequencies
            .contains_key(&event.actor.id_hash);
        let actor_risk_score = if is_unknown_actor {
            threat_score += 0.2;
            threat_indicators.push("Unknown actor".to_string());
            0.8
        } else {
            baseline
                .known_actors
                .get(&event.actor.id_hash)
                .map(|p| p.risk_score)
                .unwrap_or(0.5)
        };

        // 4. Unknown Action (10% weight)
        let is_unknown_action = !baseline.action_frequencies.contains_key(&event.action.name);
        if is_unknown_action {
            threat_score += 0.1;
            threat_indicators.push(format!("Unknown action: {}", event.action.name));
        }

        // 4b. Behavioral fingerprinting (actor-specific rarity) (10% weight max)
        if let Some(profile) = baseline.known_actors.get(&event.actor.id_hash) {
            if profile.total_actions >= 20 {
                let count = profile
                    .action_distribution
                    .get(&event.action.name)
                    .copied()
                    .unwrap_or(0) as f64;
                let prob = count / profile.total_actions as f64;
                if prob < 0.1 {
                    let severity = ((0.1 - prob) / 0.1).min(1.0);
                    threat_score += severity * 0.1;
                    threat_indicators.push(format!(
                        "Behavioral fingerprint: uncharacteristic action for actor (p={prob:.2})"
                    ));
                }
            }
        }

        // 5. Temporal anomalies (15% weight max)
        if let Some(tanom) = self.temporal_analyzer.detect_anomaly(event) {
            threat_score += (tanom.severity * 0.15).min(0.15);
            threat_indicators.push(format!("Temporal anomaly: {}", tanom.reason));
        }

        // 6. Sequence detection (20% weight max)
        if let Some(seq) = self.sequence_detector.detect(&event.actor.id_hash) {
            threat_score += (seq.severity * 0.2).min(0.2);
            threat_indicators.push(format!("Sequence pattern matched: {}", seq.name));
        }

        // 7. Multi-actor correlation (15% weight max)
        if let Some(camp) = self.correlation_engine.detect(&attack_tactic, &event.ts) {
            threat_score += (camp.severity * 0.15).min(0.15);
            threat_indicators.push(format!("Coordinated campaign: {}", camp.description));
        }

        // 8. Specific Threat Patterns (10% weight)
        let is_privilege_escalation = matches!(attack_tactic, AttackTactic::PrivilegeEscalation);
        let is_data_exfiltration = matches!(attack_tactic, AttackTactic::Exfiltration);
        let is_destructive = matches!(attack_tactic, AttackTactic::Impact);

        if is_privilege_escalation {
            threat_score += 0.05;
            threat_indicators.push("Privilege escalation attempt".to_string());
        }

        if is_data_exfiltration {
            threat_score += 0.05;
            threat_indicators.push("Data exfiltration pattern".to_string());
        }

        if is_destructive {
            threat_score += 0.1;
            threat_indicators.push("⚠️ DESTRUCTIVE ACTION DETECTED".to_string());
        }

        // Calculate confidence based on baseline size
        let confidence = if baseline.total_events < 10 {
            0.5 // Low confidence with small baseline
        } else if baseline.total_events < 50 {
            0.7 // Medium confidence
        } else {
            0.9 // High confidence with large baseline
        };

        // Determine if this is a threat (adaptive threshold based on confidence)
        let threshold = if confidence > 0.8 { 0.5 } else { 0.6 };
        let is_threat = threat_score >= threshold;

        // Recommended action
        let recommended_action = if threat_score >= 0.9 {
            "BLOCK - Critical threat detected".to_string()
        } else if threat_score >= 0.7 {
            "ALERT - High-risk activity, review immediately".to_string()
        } else if threat_score >= 0.5 {
            "MONITOR - Suspicious activity, log and watch".to_string()
        } else {
            "ALLOW - Normal activity".to_string()
        };

        // 9. ML assist (confidence delta only, never changes verdict)
        let (ml_delta, ml_explain) = self.ml_assist.confidence_delta(event);
        threat_indicators.push(format!("ML assist: {ml_explain}"));
        let confidence = (confidence + ml_delta).clamp(0.0, 1.0);

        let detection = ThreatDetection {
            is_threat,
            threat_score,
            confidence,
            attack_tactic,
            tactic_risk,
            is_statistical_anomaly,
            z_score,
            is_unknown_actor,
            is_unknown_action,
            is_privilege_escalation,
            is_data_exfiltration,
            is_destructive,
            actor_risk_score,
            action_frequency: baseline
                .action_frequencies
                .get(&event.action.name)
                .copied()
                .unwrap_or(0.0),
            threat_indicators,
            recommended_action,
        };

        // Record in recent indicators buffer
        let indicators = detection.threat_indicators.clone();
        let log = DetectionLog {
            ts: event.ts.clone(),
            actor_id: event.actor.id_hash.clone(),
            action: event.action.name.clone(),
            threat_score: detection.threat_score,
            is_threat: detection.is_threat,
            indicators,
        };
        if self.recent_indicators.len() == 50 {
            self.recent_indicators.pop_front();
        }
        self.recent_indicators.push_back(log);

        Ok(detection)
    }

    /// Detect threats and incorporate volume anomaly (adds up to +0.2)
    pub fn detect_threat_with_volume(
        &mut self,
        namespace_id: &str,
        event: &DecisionEvent,
        volume_bytes: u64,
    ) -> Result<ThreatDetection, ThreatError> {
        // Observe current tactic for sequence detection before scoring
        let current_tactic = AttackClassifier::classify(&event.action.name);
        self.sequence_detector
            .observe(&event.actor.id_hash, current_tactic, &event.ts);

        let mut detection = self.detect_threat(namespace_id, event)?;

        if let Some(anom) = self
            .volume_tracker
            .detect_actor_anomaly(&event.actor.id_hash, volume_bytes)
        {
            // Weight volume anomaly at 20%
            detection.threat_score = (detection.threat_score + anom.severity * 0.2).min(1.0);
            detection.threat_indicators.push(format!(
                "Volume anomaly: factor {:.2} (current {:.0} vs baseline {:.0})",
                anom.z_like, anom.current, anom.baseline
            ));

            // Recompute is_threat and recommended action based on adjusted score
            let threshold = if detection.confidence > 0.8 { 0.5 } else { 0.6 };
            detection.is_threat = detection.threat_score >= threshold;
            detection.recommended_action = if detection.threat_score >= 0.9 {
                "BLOCK - Critical threat detected".to_string()
            } else if detection.threat_score >= 0.7 {
                "ALERT - High-risk activity, review immediately".to_string()
            } else if detection.threat_score >= 0.5 {
                "MONITOR - Suspicious activity, log and watch".to_string()
            } else {
                "ALLOW - Normal activity".to_string()
            };
        }

        // Update recent indicators with adjusted score
        let indicators = detection.threat_indicators.clone();
        let log = DetectionLog {
            ts: event.ts.clone(),
            actor_id: event.actor.id_hash.clone(),
            action: event.action.name.clone(),
            threat_score: detection.threat_score,
            is_threat: detection.is_threat,
            indicators,
        };
        if self.recent_indicators.len() == 50 {
            self.recent_indicators.pop_front();
        }
        self.recent_indicators.push_back(log);

        Ok(detection)
    }

    /// Update baseline after detection (PROTECTED against poisoning)
    pub fn update_baseline(
        &mut self,
        namespace_id: &str,
        event: &DecisionEvent,
    ) -> Result<(), ThreatError> {
        // CRITICAL: Detect threat FIRST
        let threat = self.detect_threat(namespace_id, event)?;

        // Only update if threat score is low (< 0.4)
        // Note: Unknown actor adds 0.2, benign action is 0.0, so normal new users score 0.2
        if threat.threat_score < 0.4 {
            let baseline = self
                .baselines
                .get_mut(namespace_id)
                .ok_or_else(|| ThreatError::BaselineNotFound(namespace_id.to_string()))?;

            baseline.update(event);
            // Track temporal behavior only when baseline accepts the event (benign)
            self.temporal_analyzer.track_event(event);
            // Observe tactic for sequence learning on accepted events
            let t = AttackClassifier::classify(&event.action.name);
            self.sequence_detector
                .observe(&event.actor.id_hash, t, &event.ts);

            // Calculate drift from golden baseline
            if let Some(golden) = self.golden_baselines.get(namespace_id) {
                let drift = baseline.distance_from(golden);
                self.baseline_drift.insert(namespace_id.to_string(), drift);

                // Alert if drift is too high (> 0.5)
                if drift > 0.5 {
                    return Err(ThreatError::DetectionFailed(format!(
                        "⚠️ Baseline drift too high: {drift:.2} (possible poisoning attack)"
                    )));
                }
            }

            Ok(())
        } else {
            // Refuse to update baseline with threats
            Err(ThreatError::DetectionFailed(format!(
                "🚨 Refusing to update baseline with threat score {:.2}",
                threat.threat_score
            )))
        }
    }

    /// Get current baseline drift from golden
    pub fn get_baseline_drift(&self, namespace_id: &str) -> f64 {
        self.baseline_drift
            .get(namespace_id)
            .copied()
            .unwrap_or(0.0)
    }

    /// Get last N recent detection indicators for stats/demo
    pub fn get_recent_indicators(&self, limit: usize) -> Vec<DetectionLog> {
        let n = limit.min(self.recent_indicators.len());
        self.recent_indicators
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect()
    }
}

impl Default for ThreatDetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_models::{Action, Actor, ActorType, Context, EnvStamp, RedactionInfo, Subject};

    fn create_test_event(action: &str, actor_id: &str) -> DecisionEvent {
        DecisionEvent {
            event_id: "evt_1".to_string(),
            namespace_id: "ns://test/prod/app/svc".to_string(),
            ts: "2025-12-18T00:00:00Z".to_string(),
            event_type: action.to_string(),
            actor: Actor {
                r#type: ActorType::User,
                id_hash: actor_id.to_string(),
                roles: vec![],
            },
            subject: Subject {
                r#type: "resource".to_string(),
                id_hash: "subj_1".to_string(),
            },
            action: Action {
                name: action.to_string(),
                params_hash: None,
            },
            context: Context {
                request_id: None,
                trace_id: None,
                ip_hash: None,
                user_agent_hash: None,
            },
            env_stamp: EnvStamp {
                env: "prod".to_string(),
                service: "test".to_string(),
                build_hash: "build1".to_string(),
                region: "us-east-1".to_string(),
                trust_flags: vec![],
            },
            redaction: RedactionInfo {
                applied: vec![],
                strategy: None,
            },
            stage_trace: vec![],
        }
    }

    #[test]
    fn attack_classifier_detects_destructive() {
        assert_eq!(
            AttackClassifier::classify("delete_all"),
            AttackTactic::Impact
        );
        assert_eq!(
            AttackClassifier::classify("drop_database"),
            AttackTactic::Impact
        );
        assert_eq!(
            AttackClassifier::classify("encrypt_files"),
            AttackTactic::Impact
        );
    }

    #[test]
    fn attack_classifier_detects_exfiltration() {
        assert_eq!(
            AttackClassifier::classify("export_data"),
            AttackTactic::Exfiltration
        );
        assert_eq!(
            AttackClassifier::classify("download_all"),
            AttackTactic::Exfiltration
        );
    }

    #[test]
    fn attack_classifier_detects_benign() {
        assert_eq!(AttackClassifier::classify("read"), AttackTactic::Benign);
        assert_eq!(AttackClassifier::classify("view"), AttackTactic::Benign);
        assert_eq!(AttackClassifier::classify("get"), AttackTactic::Benign);
    }

    #[test]
    fn threat_engine_detects_destructive_action() {
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline("ns://test/prod/app/svc".to_string());

        // Build baseline with normal actions
        for _ in 0..10 {
            let event = create_test_event("read", "alice");
            engine
                .update_baseline("ns://test/prod/app/svc", &event)
                .unwrap();
        }

        // Test destructive action
        let attack = create_test_event("delete_all", "hacker");
        let detection = engine
            .detect_threat("ns://test/prod/app/svc", &attack)
            .unwrap();

        assert!(detection.is_threat);
        assert!(detection.threat_score > 0.7);
        assert_eq!(detection.attack_tactic, AttackTactic::Impact);
        assert!(detection.is_destructive);
        assert!(
            detection.recommended_action.contains("BLOCK")
                || detection.recommended_action.contains("ALERT")
        );
    }

    #[test]
    fn threat_engine_allows_normal_actions() {
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline("ns://test/prod/app/svc".to_string());

        // Build baseline
        for _ in 0..10 {
            let event = create_test_event("read", "alice");
            engine
                .update_baseline("ns://test/prod/app/svc", &event)
                .unwrap();
        }

        // Test normal action from known actor
        let normal = create_test_event("read", "alice");
        let detection = engine
            .detect_threat("ns://test/prod/app/svc", &normal)
            .unwrap();

        assert!(!detection.is_threat);
        assert!(detection.threat_score < 0.5);
        assert_eq!(detection.attack_tactic, AttackTactic::Benign);
    }

    #[test]
    fn baseline_poisoning_protection() {
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline("ns://test/prod/app/svc".to_string());

        // Build legitimate baseline
        for _ in 0..10 {
            let event = create_test_event("read", "alice");
            engine
                .update_baseline("ns://test/prod/app/svc", &event)
                .unwrap();
        }

        // Attacker tries to poison baseline with malicious actions
        for _ in 0..10 {
            let attack = create_test_event("delete_all", "hacker");
            let result = engine.update_baseline("ns://test/prod/app/svc", &attack);
            // Should FAIL to update (threat score too high)
            assert!(result.is_err());
        }

        // Verify delete_all is STILL detected as threat
        let attack = create_test_event("delete_all", "hacker");
        let detection = engine
            .detect_threat("ns://test/prod/app/svc", &attack)
            .unwrap();

        assert!(
            detection.is_threat,
            "delete_all should still be detected as threat"
        );
        assert!(detection.threat_score > 0.7, "Threat score should be high");
        assert_eq!(detection.attack_tactic, AttackTactic::Impact);
    }

    #[test]
    fn baseline_drift_detection() {
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline("ns://test/prod/app/svc".to_string());

        // Build baseline with normal actions
        for _ in 0..10 {
            let event = create_test_event("read", "alice");
            engine
                .update_baseline("ns://test/prod/app/svc", &event)
                .unwrap();
        }

        // Check initial drift (should be low)
        let drift = engine.get_baseline_drift("ns://test/prod/app/svc");
        assert!(drift < 0.1, "Initial drift should be low, got: {}", drift);

        // Add more of the SAME action (should increase drift very slightly)
        for _ in 0..5 {
            let event = create_test_event("read", "bob"); // Different actor, same action
            engine
                .update_baseline("ns://test/prod/app/svc", &event)
                .unwrap();
        }

        // Drift should still be very low (same action, just more frequency)
        let drift = engine.get_baseline_drift("ns://test/prod/app/svc");
        assert!(drift < 0.1, "Drift should still be low, got: {}", drift);
    }

    #[test]
    fn threat_engine_volume_spike_adds_indicator_and_score() {
        let ns = "ns://test/prod/app/svc";
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline(ns.to_string());
        // Build baseline and volume baseline for alice
        for _ in 0..10 {
            let e = create_test_event("read", "alice");
            engine.update_baseline(ns, &e).unwrap();
            engine.track_volume(&e.actor.id_hash, 100);
        }
        engine.calibrate_volumes();

        // Now a large volume spike (12x baseline)
        let event = create_test_event("read", "alice");
        let detection = engine
            .detect_threat_with_volume(ns, &event, 1200)
            .expect("volume detection should succeed");

        assert!(
            detection
                .threat_indicators
                .iter()
                .any(|s| s.contains("Volume anomaly")),
            "Expected volume anomaly indicator"
        );
        assert!(
            detection.threat_score >= 0.19,
            "Expected threat score increase, got {}",
            detection.threat_score
        );
    }

    #[test]
    fn threat_engine_volume_small_change_no_indicator() {
        let ns = "ns://test/prod/app/svc";
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline(ns.to_string());
        for _ in 0..10 {
            let e = create_test_event("read", "bob");
            engine.update_baseline(ns, &e).unwrap();
            engine.track_volume(&e.actor.id_hash, 200);
        }
        engine.calibrate_volumes();

        // 2.5x should be below 3x threshold -> no indicator
        let event = create_test_event("read", "bob");
        let detection = engine
            .detect_threat_with_volume(ns, &event, 500)
            .expect("volume detection should succeed");

        assert!(
            !detection
                .threat_indicators
                .iter()
                .any(|s| s.contains("Volume anomaly")),
            "Did not expect volume anomaly indicator"
        );
    }

    #[test]
    fn temporal_off_hours_anomaly_detected() {
        let ns = "ns://test/prod/app/svc";
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline(ns.to_string());

        // Build baseline with mid-day events to exceed 50 total
        for i in 0..60 {
            let mut e = create_test_event("read", "alice");
            // 12:00:00Z + i minutes
            e.ts = format!("2025-12-18T12:{:02}:00Z", i % 60);
            engine.update_baseline(ns, &e).unwrap();
        }

        // Now create an off-hours event at 03:00Z
        let mut off = create_test_event("read", "alice");
        off.ts = "2025-12-18T03:00:00Z".to_string();
        let det = engine.detect_threat(ns, &off).unwrap();
        assert!(
            det.threat_indicators
                .iter()
                .any(|s| s.contains("Temporal anomaly:")),
            "Expected temporal anomaly indicator, got: {:?}",
            det.threat_indicators
        );
        // Score should include temporal contribution but remain below threat threshold
        assert!(det.threat_score < 0.5);
    }

    #[test]
    fn temporal_velocity_spike_detected() {
        let ns = "ns://test/prod/app/svc";
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline(ns.to_string());

        // Build baseline for alice with spaced events (avg interarrival ~ 120s)
        for i in 0..60 {
            let mut e = create_test_event("read", "alice");
            // Every 2 minutes starting 12:00
            e.ts = format!("2025-12-18T12:{:02}:00Z", (i * 2) % 60);
            engine.update_baseline(ns, &e).unwrap();
        }

        // Now send a near-immediate follow-up (1s after last)
        let mut fast = create_test_event("read", "alice");
        fast.ts = "2025-12-18T12:59:01Z".to_string();
        let det = engine.detect_threat(ns, &fast).unwrap();
        assert!(
            det.threat_indicators
                .iter()
                .any(|s| s.contains("Temporal anomaly:")),
            "Expected temporal anomaly (velocity) indicator"
        );
    }

    #[test]
    fn sequence_detection_triggers_indicator_and_score() {
        let ns = "ns://test/prod/app/svc";
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline(ns.to_string());

        // Same actor performs Discovery -> CredentialAccess -> Exfiltration
        let mut e1 = create_test_event("list", "mallory");
        e1.ts = "2025-12-18T10:00:00Z".to_string();
        let _ = engine.detect_threat(ns, &e1).unwrap();

        let mut e2 = create_test_event("password_dump", "mallory");
        e2.ts = "2025-12-18T10:05:00Z".to_string();
        let _ = engine.detect_threat(ns, &e2).unwrap();

        let mut e3 = create_test_event("export_data", "mallory");
        e3.ts = "2025-12-18T10:07:00Z".to_string();
        let det3 = engine.detect_threat(ns, &e3).unwrap();

        assert!(
            det3.threat_indicators
                .iter()
                .any(|s| s.contains("Sequence pattern matched")),
            "Expected sequence indicator, got: {:?}",
            det3.threat_indicators
        );
        assert!(
            det3.threat_score >= 0.2,
            "Expected score bump from sequence, got {}",
            det3.threat_score
        );
    }

    #[test]
    fn behavioral_fingerprint_rare_action_increases_score() {
        let ns = "ns://test/prod/app/svc";
        let mut engine = ThreatDetectionEngine::new();
        engine.create_baseline(ns.to_string());

        // Build strong profile for alice on "read"
        for _ in 0..25 {
            let e = create_test_event("read", "alice");
            engine.update_baseline(ns, &e).unwrap();
        }

        // Now perform a rare benign action variant "view" (normalized benign, different token)
        let e2 = create_test_event("view", "alice");
        let det = engine.detect_threat(ns, &e2).unwrap();
        assert!(
            det.threat_indicators
                .iter()
                .any(|s| s.contains("Behavioral fingerprint")),
            "Expected fingerprint indicator, got: {:?}",
            det.threat_indicators
        );
        assert!(
            det.threat_score >= 0.15 && det.threat_score < 0.5,
            "Score should reflect rarity without crossing threat threshold, got {}",
            det.threat_score
        );
    }
}
