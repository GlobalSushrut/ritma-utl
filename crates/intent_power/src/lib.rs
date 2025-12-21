use common_models::DecisionEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntentError {
    #[error("baseline not found: {0}")]
    BaselineNotFound(String),
    #[error("drift detected: {0}")]
    DriftDetected(String),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, IntentError>;

/// Intent baseline for a namespace capturing normal behavior patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentBaseline {
    pub namespace_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub event_type_frequencies: HashMap<String, f64>,
    pub actor_patterns: HashMap<String, ActorPattern>,
    pub temporal_patterns: TemporalPattern,
    pub action_sequences: Vec<ActionSequence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorPattern {
    pub typical_actions: Vec<String>,
    pub typical_subjects: Vec<String>,
    pub frequency: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalPattern {
    pub hourly_distribution: Vec<f64>, // 24 hours
    pub daily_distribution: Vec<f64>,  // 7 days
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSequence {
    pub sequence: Vec<String>,
    pub frequency: f64,
}

/// Drift detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDetection {
    pub has_drift: bool,
    pub drift_score: f64,
    pub drift_reasons: Vec<String>,
    pub event_type_drift: Option<f64>,
    pub actor_drift: Option<f64>,
    pub temporal_drift: Option<f64>,
}

/// Intent baseline manager
pub struct IntentBaselineManager {
    baselines: HashMap<String, IntentBaseline>,
}

impl IntentBaselineManager {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
        }
    }

    /// Create a new baseline for a namespace
    pub fn create_baseline(&mut self, namespace_id: String) -> IntentBaseline {
        let baseline = IntentBaseline {
            namespace_id: namespace_id.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            event_type_frequencies: HashMap::new(),
            actor_patterns: HashMap::new(),
            temporal_patterns: TemporalPattern {
                hourly_distribution: vec![0.0; 24],
                daily_distribution: vec![0.0; 7],
            },
            action_sequences: Vec::new(),
        };
        
        self.baselines.insert(namespace_id, baseline.clone());
        baseline
    }

    /// Get baseline for a namespace
    pub fn get_baseline(&self, namespace_id: &str) -> Result<&IntentBaseline> {
        self.baselines
            .get(namespace_id)
            .ok_or_else(|| IntentError::BaselineNotFound(namespace_id.to_string()))
    }

    /// Update baseline with new event
    pub fn update_baseline(&mut self, namespace_id: &str, event: &DecisionEvent) -> Result<()> {
        let baseline = self.baselines
            .get_mut(namespace_id)
            .ok_or_else(|| IntentError::BaselineNotFound(namespace_id.to_string()))?;

        // Update event type frequencies
        *baseline.event_type_frequencies
            .entry(event.event_type.clone())
            .or_insert(0.0) += 1.0;

        // Update actor patterns
        let actor_key = event.actor.id_hash.clone();
        baseline.actor_patterns
            .entry(actor_key)
            .or_insert_with(|| ActorPattern {
                typical_actions: Vec::new(),
                typical_subjects: Vec::new(),
                frequency: 0.0,
            })
            .frequency += 1.0;

        baseline.updated_at = chrono::Utc::now().to_rfc3339();
        Ok(())
    }

    /// Detect drift from baseline
    pub fn detect_drift(
        &self,
        namespace_id: &str,
        event: &DecisionEvent,
    ) -> Result<DriftDetection> {
        let baseline = self.get_baseline(namespace_id)?;

        let mut drift_reasons = Vec::new();
        let mut drift_score = 0.0;

        // Check event type drift
        let total_events: f64 = baseline.event_type_frequencies.values().sum();
        let event_type_freq = baseline.event_type_frequencies
            .get(&event.event_type)
            .copied()
            .unwrap_or(0.0);
        
        let event_type_drift = if total_events > 0.0 && (event_type_freq / total_events) < 0.01 {
            drift_reasons.push(format!("Rare event type: {}", event.event_type));
            drift_score += 0.3;
            Some(0.3)
        } else if total_events == 0.0 || event_type_freq == 0.0 {
            drift_reasons.push(format!("Unknown event type: {}", event.event_type));
            drift_score += 0.3;
            Some(0.3)
        } else {
            None
        };

        // Check actor drift
        let actor_drift = if !baseline.actor_patterns.contains_key(&event.actor.id_hash) {
            drift_reasons.push(format!("Unknown actor: {}", event.actor.id_hash));
            drift_score += 0.4;
            Some(0.4)
        } else {
            None
        };

        let has_drift = drift_score > 0.5;

        Ok(DriftDetection {
            has_drift,
            drift_score,
            drift_reasons,
            event_type_drift,
            actor_drift,
            temporal_drift: None,
        })
    }
}

impl Default for IntentBaselineManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_models::{Actor, ActorType, Subject, Action, Context, EnvStamp, RedactionInfo};

    fn create_test_event(event_type: &str, actor_id: &str) -> DecisionEvent {
        DecisionEvent {
            event_id: "evt_1".to_string(),
            namespace_id: "ns://test/prod/app/svc".to_string(),
            ts: "2025-12-18T00:00:00Z".to_string(),
            event_type: event_type.to_string(),
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
                name: "read".to_string(),
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
    fn baseline_manager_creates_baseline() {
        let mut manager = IntentBaselineManager::new();
        let baseline = manager.create_baseline("ns://test/prod/app/svc".to_string());
        
        assert_eq!(baseline.namespace_id, "ns://test/prod/app/svc");
        assert!(baseline.event_type_frequencies.is_empty());
    }

    #[test]
    fn baseline_manager_updates_baseline() {
        let mut manager = IntentBaselineManager::new();
        manager.create_baseline("ns://test/prod/app/svc".to_string());
        
        let event = create_test_event("AUTH", "user_1");
        manager.update_baseline("ns://test/prod/app/svc", &event).expect("update");
        
        let baseline = manager.get_baseline("ns://test/prod/app/svc").expect("get");
        assert_eq!(baseline.event_type_frequencies.get("AUTH"), Some(&1.0));
    }

    #[test]
    fn baseline_manager_detects_drift() {
        let mut manager = IntentBaselineManager::new();
        manager.create_baseline("ns://test/prod/app/svc".to_string());
        
        // Add some baseline events
        let event1 = create_test_event("AUTH", "user_1");
        manager.update_baseline("ns://test/prod/app/svc", &event1).expect("update");
        
        // Test with unknown event type AND unknown actor to exceed drift threshold
        let event2 = create_test_event("RARE_EVENT", "unknown_user");
        let drift = manager.detect_drift("ns://test/prod/app/svc", &event2).expect("detect");
        
        assert!(drift.has_drift);
        assert!(!drift.drift_reasons.is_empty());
        assert!(drift.drift_score > 0.5); // Should be 0.3 + 0.4 = 0.7
    }
}
