//! Multi-actor correlation: detect coordinated behavior within time windows

use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Timelike, Utc};
use crate::AttackTactic;

#[derive(Debug, Clone)]
pub struct Campaign {
    pub description: String,
    pub actor_count: usize,
    pub severity: f64, // 0.0 - 1.0
}

#[derive(Default)]
pub struct CorrelationEngine {
    // key: (tactic, bucket_key)
    windows: HashMap<(AttackTactic, i64), HashSet<String>>, // actors per tactic per time bucket
    bucket_minutes: i64,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self { windows: HashMap::new(), bucket_minutes: 10 }
    }

    fn bucket(&self, ts: &DateTime<Utc>) -> i64 {
        let minutes = (ts.minute() as i64) + (ts.hour() as i64) * 60;
        minutes / self.bucket_minutes
    }

    pub fn observe(&mut self, actor_id: &str, tactic: AttackTactic, ts_str: &str) {
        if let Ok(ts) = DateTime::parse_from_rfc3339(ts_str) {
            let ts_utc = ts.with_timezone(&Utc);
            let bucket = self.bucket(&ts_utc);
            let set = self.windows.entry((tactic, bucket)).or_default();
            set.insert(actor_id.to_string());
        }
    }

    pub fn detect(&self, tactic: &AttackTactic, ts_str: &str) -> Option<Campaign> {
        let ts = DateTime::parse_from_rfc3339(ts_str).ok()?.with_timezone(&Utc);
        let bucket = self.bucket(&ts);
        let count = self.windows.get(&(tactic.clone(), bucket)).map(|s| s.len()).unwrap_or(0);
        if count >= 3 {
            // Scale severity: 3 actors -> 0.4, 5 actors -> 0.8, 7+ -> 1.0
            // Linear steps of 0.2 per additional actor beyond 3, capped at 1.0
            let severity = (0.4 + 0.2 * ((count as i64 - 3).max(0) as f64)).min(1.0);
            Some(Campaign {
                description: format!("Coordinated behavior: {:?} across {} actors within {} min", tactic, count, self.bucket_minutes),
                actor_count: count,
                severity,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_engine_detects_campaign() {
        let mut eng = CorrelationEngine::new();
        let t = AttackTactic::Discovery;
        // 3 different actors, same window
        eng.observe("a1", t.clone(), "2025-12-18T12:01:00Z");
        eng.observe("a2", t.clone(), "2025-12-18T12:05:00Z");
        eng.observe("a3", t.clone(), "2025-12-18T12:09:59Z");
        let c = eng.detect(&t, "2025-12-18T12:09:59Z").expect("should be campaign");
        assert!(c.actor_count >= 3);
        assert!(c.severity >= 0.4);
    }
}
