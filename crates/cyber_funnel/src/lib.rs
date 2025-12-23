use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FunnelError {
    #[error("invalid stage transition: {0}")]
    InvalidTransition(String),
    #[error("confidence violation: {0}")]
    ConfidenceViolation(String),
    #[error("silent escalation detected: {0}")]
    SilentEscalation(String),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, FunnelError>;

/// Cyber Funnel stages with monotonic confidence progression
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunnelStage {
    Observe = 1,
    Canonicalize = 2,
    Correlate = 3,
    DetectIntentDrift = 4,
    ClassifyAbusePattern = 5,
    AdvisoryAction = 6,
    ContractBoundedEnforcement = 7,
}

impl FunnelStage {
    pub fn min_confidence(&self) -> f64 {
        match self {
            FunnelStage::Observe => 0.0,
            FunnelStage::Canonicalize => 0.1,
            FunnelStage::Correlate => 0.3,
            FunnelStage::DetectIntentDrift => 0.5,
            FunnelStage::ClassifyAbusePattern => 0.7,
            FunnelStage::AdvisoryAction => 0.8,
            FunnelStage::ContractBoundedEnforcement => 0.9,
        }
    }

    pub fn next(&self) -> Option<FunnelStage> {
        match self {
            FunnelStage::Observe => Some(FunnelStage::Canonicalize),
            FunnelStage::Canonicalize => Some(FunnelStage::Correlate),
            FunnelStage::Correlate => Some(FunnelStage::DetectIntentDrift),
            FunnelStage::DetectIntentDrift => Some(FunnelStage::ClassifyAbusePattern),
            FunnelStage::ClassifyAbusePattern => Some(FunnelStage::AdvisoryAction),
            FunnelStage::AdvisoryAction => Some(FunnelStage::ContractBoundedEnforcement),
            FunnelStage::ContractBoundedEnforcement => None,
        }
    }
}

/// Stage transition record for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageTransition {
    pub from_stage: FunnelStage,
    pub to_stage: FunnelStage,
    pub confidence: f64,
    pub timestamp: String,
    pub reason: String,
}

/// Funnel progression tracker ensuring monotonic confidence
pub struct FunnelTracker {
    current_stage: FunnelStage,
    current_confidence: f64,
    transitions: Vec<StageTransition>,
}

impl FunnelTracker {
    pub fn new() -> Self {
        Self {
            current_stage: FunnelStage::Observe,
            current_confidence: 0.0,
            transitions: Vec::new(),
        }
    }

    /// Advance to next stage with confidence check
    pub fn advance(&mut self, new_confidence: f64, reason: String) -> Result<FunnelStage> {
        // Check monotonic confidence increase
        if new_confidence < self.current_confidence {
            return Err(FunnelError::ConfidenceViolation(format!(
                "Confidence decreased from {} to {}",
                self.current_confidence, new_confidence
            )));
        }

        let next_stage = self
            .current_stage
            .next()
            .ok_or_else(|| FunnelError::InvalidTransition("Already at final stage".to_string()))?;

        // Check minimum confidence for next stage
        if new_confidence < next_stage.min_confidence() {
            return Err(FunnelError::ConfidenceViolation(format!(
                "Confidence {} below minimum {} for stage {:?}",
                new_confidence,
                next_stage.min_confidence(),
                next_stage
            )));
        }

        // Record transition
        let transition = StageTransition {
            from_stage: self.current_stage,
            to_stage: next_stage,
            confidence: new_confidence,
            timestamp: chrono::Utc::now().to_rfc3339(),
            reason,
        };

        self.transitions.push(transition);
        self.current_stage = next_stage;
        self.current_confidence = new_confidence;

        Ok(next_stage)
    }

    pub fn current_stage(&self) -> FunnelStage {
        self.current_stage
    }

    pub fn current_confidence(&self) -> f64 {
        self.current_confidence
    }

    pub fn transitions(&self) -> &[StageTransition] {
        &self.transitions
    }

    /// Check for silent escalation (stage jump without proper progression)
    pub fn validate_no_silent_escalation(&self) -> Result<()> {
        for window in self.transitions.windows(2) {
            let prev = &window[0];
            let curr = &window[1];

            // Check if stages are consecutive
            if prev.to_stage.next() != Some(curr.to_stage) && prev.to_stage != curr.from_stage {
                return Err(FunnelError::SilentEscalation(format!(
                    "Non-consecutive stage transition from {:?} to {:?}",
                    prev.to_stage, curr.to_stage
                )));
            }
        }
        Ok(())
    }
}

impl Default for FunnelTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funnel_stages_have_monotonic_confidence() {
        assert!(FunnelStage::Observe.min_confidence() < FunnelStage::Canonicalize.min_confidence());
        assert!(
            FunnelStage::Canonicalize.min_confidence() < FunnelStage::Correlate.min_confidence()
        );
        assert!(
            FunnelStage::Correlate.min_confidence()
                < FunnelStage::DetectIntentDrift.min_confidence()
        );
    }

    #[test]
    fn funnel_tracker_advances_with_valid_confidence() {
        let mut tracker = FunnelTracker::new();

        assert_eq!(tracker.current_stage(), FunnelStage::Observe);

        let stage = tracker
            .advance(0.2, "canonicalized".to_string())
            .expect("advance");
        assert_eq!(stage, FunnelStage::Canonicalize);
        assert_eq!(tracker.current_confidence(), 0.2);
    }

    #[test]
    fn funnel_tracker_rejects_confidence_decrease() {
        let mut tracker = FunnelTracker::new();
        tracker.advance(0.5, "test".to_string()).expect("advance");

        let result = tracker.advance(0.3, "decrease".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn funnel_tracker_rejects_insufficient_confidence() {
        let mut tracker = FunnelTracker::new();

        // Try to advance to Canonicalize with confidence below minimum
        let result = tracker.advance(0.05, "too low".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn funnel_tracker_validates_no_silent_escalation() {
        let mut tracker = FunnelTracker::new();

        tracker.advance(0.2, "step1".to_string()).expect("advance");
        tracker.advance(0.4, "step2".to_string()).expect("advance");

        assert!(tracker.validate_no_silent_escalation().is_ok());
    }
}
