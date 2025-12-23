//! Volume semantics: detect spikes and slow-and-low exfiltration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Time window for volume tracking (placeholder for future)
#[derive(Debug, Clone, Copy)]
pub enum TimeWindow {
    OneMinute,
    OneHour,
    OneDay,
}

/// Volume statistics for an entity (actor/action/namespace)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VolumeStats {
    pub total_bytes: u64,
    pub total_records: u64,
    pub baseline_rate: f64, // bytes per record (simple baseline)
}

/// Volume anomaly detection result
#[derive(Debug, Clone)]
pub struct VolumeAnomaly {
    pub is_anomaly: bool,
    pub z_like: f64,
    pub current: f64,
    pub baseline: f64,
    pub severity: f64, // 0.0-1.0
}

/// Tracker for volumes across actors/actions
#[derive(Default)]
pub struct VolumeTracker {
    actor_volumes: HashMap<String, VolumeStats>,
}

impl VolumeTracker {
    pub fn new() -> Self {
        Self {
            actor_volumes: HashMap::new(),
        }
    }

    /// Learn from observed event volume (bytes)
    pub fn track_actor(&mut self, actor_id: &str, volume_bytes: u64) {
        let stats = self.actor_volumes.entry(actor_id.to_string()).or_default();
        stats.total_bytes = stats.total_bytes.saturating_add(volume_bytes);
        stats.total_records = stats.total_records.saturating_add(1);
    }

    /// Recompute baselines from accumulated data
    pub fn calibrate(&mut self) {
        for stats in self.actor_volumes.values_mut() {
            if stats.total_records > 0 {
                stats.baseline_rate = stats.total_bytes as f64 / stats.total_records as f64;
            }
        }
    }

    /// Detect anomaly for an incoming volume compared to learned baseline
    pub fn detect_actor_anomaly(&self, actor_id: &str, volume_bytes: u64) -> Option<VolumeAnomaly> {
        let stats = self.actor_volumes.get(actor_id)?;
        if stats.baseline_rate <= 0.0 {
            return None;
        }
        let current = volume_bytes as f64;
        let baseline = stats.baseline_rate;

        // Simple spike factor relative to baseline; treat >3x as anomalous
        let factor = current / baseline;
        if factor <= 3.0 {
            return None;
        }

        // Map factor to severity in (0,1]; 3x -> 0, 10x -> ~1
        let severity = ((factor - 3.0) / 7.0).clamp(0.0, 1.0);
        Some(VolumeAnomaly {
            is_anomaly: true,
            z_like: factor,
            current,
            baseline,
            severity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_tracker_detects_spikes() {
        let mut vt = VolumeTracker::new();
        // Learn baseline: ~100 bytes per record
        for _ in 0..20 {
            vt.track_actor("alice", 100);
        }
        vt.calibrate();
        let anom = vt
            .detect_actor_anomaly("alice", 1200)
            .expect("should find anomaly");
        assert!(anom.is_anomaly);
        assert!(
            anom.severity > 0.5,
            "expected high severity for 12x spike, got {}",
            anom.severity
        );
    }

    #[test]
    fn volume_tracker_ignores_small_changes() {
        let mut vt = VolumeTracker::new();
        for _ in 0..10 {
            vt.track_actor("bob", 200);
        }
        vt.calibrate();
        assert!(
            vt.detect_actor_anomaly("bob", 500).is_none(),
            "~2.5x should be below 3x threshold"
        );
        assert!(
            vt.detect_actor_anomaly("bob", 601).is_some(),
            "just over 3x should trigger"
        );
    }
}
