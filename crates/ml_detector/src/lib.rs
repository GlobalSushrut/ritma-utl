use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MlDetectorError {
    #[error("Behavioral anomaly detection failed: {0}")]
    BehavioralAnomalyError(String),
    #[error("Threat hunting failed: {0}")]
    ThreatHuntingError(String),
    #[error("Predictive security failed: {0}")]
    PredictiveSecurityError(String),
}

pub type Result<T> = std::result::Result<T, MlDetectorError>;

/// ML-detected anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlAnomalyAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub anomaly_type: MlAnomalyType,
    pub confidence: f64,  // 0.0-1.0
    pub severity: Severity,
    pub description: String,
    pub features: Vec<Feature>,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlAnomalyType {
    ProcessBehaviorAnomaly,
    NetworkBehaviorAnomaly,
    FilesystemBehaviorAnomaly,
    UserBehaviorAnomaly,
    SystemCallAnomaly,
    ResourceUsageAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feature {
    pub name: String,
    pub value: f64,
    pub importance: f64,  // 0.0-1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Threat hunting result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHuntingResult {
    pub hunt_id: String,
    pub timestamp: String,
    pub hypothesis: String,
    pub findings: Vec<ThreatFinding>,
    pub confidence: f64,
    pub threat_score: f64,  // 0.0-1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    pub finding_type: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub severity: Severity,
}

/// Predictive security alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictiveAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub predicted_threat: String,
    pub probability: f64,  // 0.0-1.0
    pub time_to_threat: u64,  // seconds
    pub severity: Severity,
    pub precursors: Vec<String>,
    pub recommended_preventive_action: String,
}

/// Behavioral feature vector
#[derive(Debug, Clone)]
pub struct BehavioralFeatureVector {
    pub process_creation_rate: f64,
    pub network_connection_rate: f64,
    pub file_modification_rate: f64,
    pub syscall_diversity: f64,
    pub memory_allocation_rate: f64,
    pub cpu_usage: f64,
    pub io_operations: f64,
}

impl BehavioralFeatureVector {
    /// Convert to feature array
    pub fn to_features(&self) -> Vec<f64> {
        vec![
            self.process_creation_rate,
            self.network_connection_rate,
            self.file_modification_rate,
            self.syscall_diversity,
            self.memory_allocation_rate,
            self.cpu_usage,
            self.io_operations,
        ]
    }
    
    /// Calculate distance from another vector (Euclidean)
    pub fn distance(&self, other: &Self) -> f64 {
        let self_features = self.to_features();
        let other_features = other.to_features();
        
        self_features.iter()
            .zip(other_features.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f64>()
            .sqrt()
    }
}

/// Behavioral anomaly detector (using isolation forest-like algorithm)
pub struct BehavioralAnomalyDetector {
    /// Training data (normal behavior)
    training_data: Vec<BehavioralFeatureVector>,
    
    /// Anomaly threshold
    threshold: f64,
    
    /// Detected anomalies
    anomalies: Vec<MlAnomalyAlert>,
}

impl BehavioralAnomalyDetector {
    pub fn new(threshold: f64) -> Self {
        Self {
            training_data: Vec::new(),
            threshold,
            anomalies: Vec::new(),
        }
    }
    
    /// Train on normal behavior
    pub fn train(&mut self, normal_samples: Vec<BehavioralFeatureVector>) {
        log::info!("Training behavioral anomaly detector with {} samples", normal_samples.len());
        self.training_data = normal_samples;
    }
    
    /// Detect anomalies
    pub fn detect_anomaly(&mut self, sample: BehavioralFeatureVector) -> Option<MlAnomalyAlert> {
        if self.training_data.is_empty() {
            return None;
        }
        
        // Calculate average distance to k nearest neighbors
        let k = 5.min(self.training_data.len());
        let mut distances: Vec<f64> = self.training_data.iter()
            .map(|train_sample| sample.distance(train_sample))
            .collect();
        
        distances.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let avg_distance: f64 = distances.iter().take(k).sum::<f64>() / k as f64;
        
        // Normalize to anomaly score (0.0-1.0)
        let anomaly_score = (avg_distance / 10.0).min(1.0);
        
        if anomaly_score > self.threshold {
            // Identify most anomalous features
            let features = vec![
                Feature {
                    name: "process_creation_rate".to_string(),
                    value: sample.process_creation_rate,
                    importance: 0.9,
                },
                Feature {
                    name: "network_connection_rate".to_string(),
                    value: sample.network_connection_rate,
                    importance: 0.85,
                },
                Feature {
                    name: "syscall_diversity".to_string(),
                    value: sample.syscall_diversity,
                    importance: 0.8,
                },
            ];
            
            let alert = MlAnomalyAlert {
                alert_id: format!("ml_{}", uuid::Uuid::new_v4()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                anomaly_type: MlAnomalyType::ProcessBehaviorAnomaly,
                confidence: anomaly_score,
                severity: if anomaly_score > 0.9 {
                    Severity::Critical
                } else if anomaly_score > 0.7 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                description: format!("Behavioral anomaly detected (score: {:.2})", anomaly_score),
                features,
                recommended_action: "Investigate process behavior, check for malware".to_string(),
            };
            
            log::warn!("🟠 ML ANOMALY: Behavioral anomaly detected (score: {:.2})", anomaly_score);
            self.anomalies.push(alert.clone());
            return Some(alert);
        }
        
        None
    }
    
    /// Get all anomalies
    pub fn get_anomalies(&self) -> &[MlAnomalyAlert] {
        &self.anomalies
    }
}

/// Automated threat hunter
pub struct AutomatedThreatHunter {
    /// Threat hypotheses
    hypotheses: Vec<ThreatHypothesis>,
    
    /// Hunt results
    results: Vec<ThreatHuntingResult>,
}

#[derive(Debug, Clone)]
struct ThreatHypothesis {
    name: String,
    description: String,
    indicators: Vec<String>,
    query_patterns: Vec<String>,
}

impl AutomatedThreatHunter {
    pub fn new() -> Self {
        let mut hunter = Self {
            hypotheses: Vec::new(),
            results: Vec::new(),
        };
        
        // Load default threat hypotheses
        hunter.hypotheses = vec![
            ThreatHypothesis {
                name: "Living off the Land".to_string(),
                description: "Attacker using legitimate system tools".to_string(),
                indicators: vec![
                    "powershell.exe".to_string(),
                    "wmic.exe".to_string(),
                    "certutil.exe".to_string(),
                ],
                query_patterns: vec![
                    "process_name:powershell AND cmdline:*DownloadString*".to_string(),
                ],
            },
            ThreatHypothesis {
                name: "Credential Dumping".to_string(),
                description: "Attacker attempting to steal credentials".to_string(),
                indicators: vec![
                    "lsass.exe".to_string(),
                    "mimikatz".to_string(),
                    "procdump".to_string(),
                ],
                query_patterns: vec![
                    "process_access:lsass.exe".to_string(),
                ],
            },
            ThreatHypothesis {
                name: "Data Exfiltration".to_string(),
                description: "Large data transfers to external IPs".to_string(),
                indicators: vec![
                    "large_upload".to_string(),
                    "external_ip".to_string(),
                ],
                query_patterns: vec![
                    "network_bytes_sent:>10000000".to_string(),
                ],
            },
        ];
        
        hunter
    }
    
    /// Hunt for threats based on hypothesis
    pub fn hunt(&mut self, hypothesis_name: &str, evidence: &HashMap<String, Vec<String>>) -> Option<ThreatHuntingResult> {
        let hypothesis = self.hypotheses.iter()
            .find(|h| h.name == hypothesis_name)?;
        
        let mut findings = Vec::new();
        let mut total_matches = 0;
        
        // Check for indicators in evidence
        for indicator in &hypothesis.indicators {
            if let Some(matches) = evidence.get(indicator) {
                if !matches.is_empty() {
                    total_matches += matches.len();
                    findings.push(ThreatFinding {
                        finding_type: "Indicator Match".to_string(),
                        description: format!("Found {} instances of {}", matches.len(), indicator),
                        indicators: matches.clone(),
                        severity: Severity::High,
                    });
                }
            }
        }
        
        if !findings.is_empty() {
            let confidence = (total_matches as f64 / hypothesis.indicators.len() as f64).min(1.0);
            let threat_score = confidence * 0.8; // Adjust based on severity
            
            let result = ThreatHuntingResult {
                hunt_id: format!("hunt_{}", uuid::Uuid::new_v4()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                hypothesis: hypothesis.name.clone(),
                findings,
                confidence,
                threat_score,
            };
            
            log::warn!("🎯 THREAT HUNT: {} (confidence: {:.2}, threat_score: {:.2})",
                      hypothesis.name, confidence, threat_score);
            self.results.push(result.clone());
            return Some(result);
        }
        
        None
    }
    
    /// Get all hunt results
    pub fn get_results(&self) -> &[ThreatHuntingResult] {
        &self.results
    }
}

impl Default for AutomatedThreatHunter {
    fn default() -> Self {
        Self::new()
    }
}

/// Predictive security engine
pub struct PredictiveSecurityEngine {
    /// Historical attack patterns
    attack_patterns: Vec<AttackPattern>,
    
    /// Predictive alerts
    predictions: Vec<PredictiveAlert>,
}

#[derive(Debug, Clone)]
struct AttackPattern {
    name: String,
    precursors: Vec<String>,
    avg_time_to_attack: u64,  // seconds
}

impl PredictiveSecurityEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            attack_patterns: Vec::new(),
            predictions: Vec::new(),
        };
        
        // Load known attack patterns
        engine.attack_patterns = vec![
            AttackPattern {
                name: "Ransomware Attack".to_string(),
                precursors: vec![
                    "reconnaissance".to_string(),
                    "credential_access".to_string(),
                    "lateral_movement".to_string(),
                ],
                avg_time_to_attack: 3600 * 24 * 3,  // 3 days
            },
            AttackPattern {
                name: "Data Breach".to_string(),
                precursors: vec![
                    "initial_access".to_string(),
                    "privilege_escalation".to_string(),
                    "collection".to_string(),
                ],
                avg_time_to_attack: 3600 * 24 * 7,  // 7 days
            },
        ];
        
        engine
    }
    
    /// Predict future threats based on observed precursors
    pub fn predict_threat(&mut self, observed_precursors: &[String]) -> Option<PredictiveAlert> {
        for pattern in &self.attack_patterns {
            // Check how many precursors match
            let matches: Vec<_> = pattern.precursors.iter()
                .filter(|p| observed_precursors.contains(p))
                .collect();
            
            let match_ratio = matches.len() as f64 / pattern.precursors.len() as f64;
            
            // If we've seen most precursors, predict the attack
            if match_ratio > 0.6 {
                let probability = match_ratio * 0.9;  // Scale to probability
                let time_to_threat = (pattern.avg_time_to_attack as f64 * (1.0 - match_ratio)) as u64;
                
                let alert = PredictiveAlert {
                    alert_id: format!("predict_{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    predicted_threat: pattern.name.clone(),
                    probability,
                    time_to_threat,
                    severity: if probability > 0.8 {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    precursors: matches.iter().map(|s| s.to_string()).collect(),
                    recommended_preventive_action: format!(
                        "Implement additional monitoring, isolate affected systems, prepare incident response for {}",
                        pattern.name
                    ),
                };
                
                log::error!("🔮 PREDICTIVE ALERT: {} predicted in {}s (probability: {:.2})",
                           pattern.name, time_to_threat, probability);
                self.predictions.push(alert.clone());
                return Some(alert);
            }
        }
        
        None
    }
    
    /// Get all predictions
    pub fn get_predictions(&self) -> &[PredictiveAlert] {
        &self.predictions
    }
}

impl Default for PredictiveSecurityEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Main ML detector
pub struct MlDetector {
    behavioral_detector: BehavioralAnomalyDetector,
    threat_hunter: AutomatedThreatHunter,
    predictive_engine: PredictiveSecurityEngine,
}

impl MlDetector {
    pub fn new(anomaly_threshold: f64) -> Self {
        Self {
            behavioral_detector: BehavioralAnomalyDetector::new(anomaly_threshold),
            threat_hunter: AutomatedThreatHunter::new(),
            predictive_engine: PredictiveSecurityEngine::new(),
        }
    }
    
    /// Get behavioral detector
    pub fn behavioral_detector(&mut self) -> &mut BehavioralAnomalyDetector {
        &mut self.behavioral_detector
    }
    
    /// Get threat hunter
    pub fn threat_hunter(&mut self) -> &mut AutomatedThreatHunter {
        &mut self.threat_hunter
    }
    
    /// Get predictive engine
    pub fn predictive_engine(&mut self) -> &mut PredictiveSecurityEngine {
        &mut self.predictive_engine
    }
    
    /// Get comprehensive ML report
    pub fn get_ml_report(&self) -> MlDetectorReport {
        MlDetectorReport {
            anomalies: self.behavioral_detector.get_anomalies().to_vec(),
            hunt_results: self.threat_hunter.get_results().to_vec(),
            predictions: self.predictive_engine.get_predictions().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlDetectorReport {
    pub anomalies: Vec<MlAnomalyAlert>,
    pub hunt_results: Vec<ThreatHuntingResult>,
    pub predictions: Vec<PredictiveAlert>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_behavioral_anomaly_detection() {
        let mut detector = BehavioralAnomalyDetector::new(0.7);
        
        // Train with normal samples
        let normal_samples = vec![
            BehavioralFeatureVector {
                process_creation_rate: 1.0,
                network_connection_rate: 2.0,
                file_modification_rate: 0.5,
                syscall_diversity: 0.3,
                memory_allocation_rate: 1.5,
                cpu_usage: 0.2,
                io_operations: 10.0,
            },
            BehavioralFeatureVector {
                process_creation_rate: 1.1,
                network_connection_rate: 2.1,
                file_modification_rate: 0.6,
                syscall_diversity: 0.35,
                memory_allocation_rate: 1.6,
                cpu_usage: 0.25,
                io_operations: 11.0,
            },
        ];
        
        detector.train(normal_samples);
        
        // Test with anomalous sample
        let anomalous = BehavioralFeatureVector {
            process_creation_rate: 50.0,  // Very high!
            network_connection_rate: 100.0,
            file_modification_rate: 20.0,
            syscall_diversity: 0.9,
            memory_allocation_rate: 50.0,
            cpu_usage: 0.9,
            io_operations: 1000.0,
        };
        
        let alert = detector.detect_anomaly(anomalous);
        assert!(alert.is_some());
    }
    
    #[test]
    fn test_threat_hunting() {
        let mut hunter = AutomatedThreatHunter::new();
        
        let mut evidence = HashMap::new();
        evidence.insert("powershell.exe".to_string(), vec!["cmd1".to_string(), "cmd2".to_string()]);
        evidence.insert("certutil.exe".to_string(), vec!["download".to_string()]);
        
        let result = hunter.hunt("Living off the Land", &evidence);
        assert!(result.is_some());
    }
    
    #[test]
    fn test_predictive_security() {
        let mut engine = PredictiveSecurityEngine::new();
        
        let precursors = vec![
            "reconnaissance".to_string(),
            "credential_access".to_string(),
            "lateral_movement".to_string(),
        ];
        
        let prediction = engine.predict_threat(&precursors);
        assert!(prediction.is_some());
    }
}
