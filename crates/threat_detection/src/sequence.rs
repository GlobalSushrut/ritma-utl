//! Sequence detection (kill-chain awareness)

use crate::AttackTactic;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AttackSequence {
    pub name: String,
    pub tactics: Vec<AttackTactic>,
    pub max_span_secs: i64,
    pub severity: f64, // 0.0-1.0
}

#[derive(Debug, Clone)]
pub struct SequenceMatch {
    pub name: String,
    pub severity: f64,
}

#[derive(Default)]
pub struct SequenceDetector {
    patterns: Vec<AttackSequence>,
    per_actor: HashMap<String, Vec<(AttackTactic, DateTime<Utc>)>>, // recent timeline
    max_keep: usize,
}

impl SequenceDetector {
    pub fn new() -> Self {
        let mut det = Self {
            patterns: Vec::new(),
            per_actor: HashMap::new(),
            max_keep: 20,
        };
        det.init_default_patterns();
        det
    }

    fn init_default_patterns(&mut self) {
        // Simple, representative patterns (no signatures, just structure/time)
        self.patterns.push(AttackSequence {
            name: "Recon → InitialAccess → Execution".to_string(),
            tactics: vec![
                AttackTactic::Reconnaissance,
                AttackTactic::InitialAccess,
                AttackTactic::Execution,
            ],
            max_span_secs: 60 * 30, // 30 min window
            severity: 0.8,
        });
        self.patterns.push(AttackSequence {
            name: "Discovery → CredentialAccess → Exfiltration".to_string(),
            tactics: vec![
                AttackTactic::Discovery,
                AttackTactic::CredentialAccess,
                AttackTactic::Exfiltration,
            ],
            max_span_secs: 60 * 60, // 1 hour
            severity: 0.8,
        });
        self.patterns.push(AttackSequence {
            name: "PrivilegeEscalation → LateralMovement → Collection → Exfiltration".to_string(),
            tactics: vec![
                AttackTactic::PrivilegeEscalation,
                AttackTactic::LateralMovement,
                AttackTactic::Collection,
                AttackTactic::Exfiltration,
            ],
            max_span_secs: 60 * 60 * 2, // 2 hour
            severity: 0.9,
        });
    }

    pub fn observe(&mut self, actor: &str, tactic: AttackTactic, ts_str: &str) {
        let ts = DateTime::parse_from_rfc3339(ts_str)
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let buf = self.per_actor.entry(actor.to_string()).or_default();
        buf.push((tactic, ts));
        if buf.len() > self.max_keep {
            let drop = buf.len().saturating_sub(self.max_keep);
            buf.drain(0..drop);
        }
    }

    pub fn detect(&self, actor: &str) -> Option<SequenceMatch> {
        let buf = self.per_actor.get(actor)?;
        if buf.is_empty() {
            return None;
        }

        for pat in &self.patterns {
            if let Some(span_ok) = self.tail_matches_in_order(buf, &pat.tactics) {
                if span_ok <= Duration::seconds(pat.max_span_secs) {
                    return Some(SequenceMatch {
                        name: pat.name.clone(),
                        severity: pat.severity,
                    });
                }
            }
        }
        None
    }

    fn tail_matches_in_order(
        &self,
        buf: &[(AttackTactic, DateTime<Utc>)],
        pattern: &[AttackTactic],
    ) -> Option<Duration> {
        // Attempt to match pattern against the tail of the buffer in order
        if pattern.is_empty() {
            return None;
        }
        let mut idxs: Vec<usize> = Vec::with_capacity(pattern.len());
        let mut start = 0usize;
        for want in pattern {
            let mut found = None;
            for (i, (t, _ts)) in buf.iter().enumerate().skip(start) {
                if t == want {
                    found = Some(i);
                    break;
                }
            }
            if let Some(i) = found {
                idxs.push(i);
                start = i + 1;
            } else {
                return None;
            }
        }
        let first = buf[*idxs.first()?].1;
        let last = buf[*idxs.last()?].1;
        Some(last - first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_detector_matches_simple_pattern() {
        let mut det = SequenceDetector::new();
        let actor = "alice";
        det.observe(actor, AttackTactic::Reconnaissance, "2025-12-18T12:00:00Z");
        det.observe(actor, AttackTactic::InitialAccess, "2025-12-18T12:05:00Z");
        det.observe(actor, AttackTactic::Execution, "2025-12-18T12:07:00Z");
        let m = det.detect(actor).expect("should match");
        assert!(m.name.contains("Recon"));
        assert!(m.severity >= 0.5);
    }
}
