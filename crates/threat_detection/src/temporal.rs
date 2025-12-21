//! Temporal analysis: hourly/daily baselines, off-hours and velocity

use std::collections::HashMap;
use chrono::{DateTime, Datelike, Timelike, Utc};
use common_models::DecisionEvent;

#[derive(Debug, Clone)]
pub struct TemporalAnomaly {
    pub reason: String,
    pub severity: f64, // 0.0 - 1.0
    pub hour: u32,
    pub weekday: u32, // 0=Mon
}

#[derive(Default)]
pub struct TemporalAnalyzer {
    hourly_counts: [u64; 24],
    daily_counts: [u64; 7],
    total_events: u64,

    // Per-actor velocity (EMA of interarrival seconds)
    actor_last_seen: HashMap<String, DateTime<Utc>>,    
    actor_avg_interarrival: HashMap<String, f64>,        // seconds
}

impl TemporalAnalyzer {
    pub fn new() -> Self { Self::default() }

    pub fn track_event(&mut self, event: &DecisionEvent) {
        if let Ok(ts) = DateTime::parse_from_rfc3339(&event.ts) {
            let ts_utc = ts.with_timezone(&Utc);
            let h = ts_utc.hour() as usize;
            self.hourly_counts[h] = self.hourly_counts[h].saturating_add(1);
            let d = ts_utc.weekday().num_days_from_monday() as usize;
            self.daily_counts[d] = self.daily_counts[d].saturating_add(1);
            self.total_events = self.total_events.saturating_add(1);

            // Velocity per actor
            let actor = &event.actor.id_hash;
            if let Some(prev) = self.actor_last_seen.get(actor) {
                let delta = (ts_utc - *prev).num_seconds().max(0) as f64;
                if delta > 0.0 {
                    let avg = self.actor_avg_interarrival.entry(actor.clone()).or_insert(delta);
                    // EMA with alpha=0.1
                    *avg = 0.9 * *avg + 0.1 * delta;
                }
            }
            self.actor_last_seen.insert(actor.clone(), ts_utc);
        }
    }

    pub fn detect_anomaly(&self, event: &DecisionEvent) -> Option<TemporalAnomaly> {
        // Require minimum baseline to avoid false positives
        if self.total_events < 50 {
            return None;
        }
        let ts = DateTime::parse_from_rfc3339(&event.ts).ok()?.with_timezone(&Utc);
        let hour = ts.hour();
        let weekday = ts.weekday().num_days_from_monday();

        // Off-hours model: 23-05 considered off-hours by default
        let off_hours = hour <= 5 || hour >= 23;

        // Compare hourly frequency to average
        let hour_count = self.hourly_counts[hour as usize] as f64;
        let avg_per_hour = (self.total_events as f64) / 24.0;

        // Off-hours anomaly if this hour historically low
        if off_hours && hour_count < avg_per_hour * 0.5 {
            return Some(TemporalAnomaly {
                reason: format!("Off-hours activity at {:02}h with low historical frequency", hour),
                severity: 0.6,
                hour,
                weekday,
            });
        }

        // Velocity anomaly per actor
        if let Some(avg) = self.actor_avg_interarrival.get(&event.actor.id_hash) {
            if let Some(prev) = self.actor_last_seen.get(&event.actor.id_hash) {
                let delta = (ts - *prev).num_seconds().max(0) as f64;
                if *avg > 0.0 {
                    let ratio = delta / *avg; // < 1.0 means faster than usual
                    if ratio < 0.6 { // significantly faster (<60% of avg)
                        let severity = ((1.0 - ratio) * 0.8).min(0.8); // up to 0.8 weight
                        return Some(TemporalAnomaly {
                            reason: format!("Velocity spike: interarrival {:.1}s vs avg {:.1}s", delta, avg),
                            severity,
                            hour,
                            weekday,
                        });
                    }
                }
            }
        }

        None
    }
}
