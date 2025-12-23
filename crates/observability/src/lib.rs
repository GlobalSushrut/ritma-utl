use lazy_static::lazy_static;
use prometheus::{Counter, Encoder, Histogram, HistogramOpts, IntGauge, Registry, TextEncoder};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // Trace metrics
    pub static ref TRACES_INGESTED: Counter = Counter::new(
        "ritma_traces_ingested_total",
        "Total number of trace events ingested"
    ).unwrap();

    pub static ref NOVEL_EGRESS: Counter = Counter::new(
        "ritma_novel_egress_total",
        "Total number of novel egress endpoints detected"
    ).unwrap();

    pub static ref AUTH_FAILURES: Counter = Counter::new(
        "ritma_auth_failures_total",
        "Total number of authentication failures"
    ).unwrap();

    // Window metrics
    pub static ref WINDOW_PROCESSING_TIME: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "ritma_window_processing_seconds",
            "Time to process a window"
        )
    ).unwrap();

    pub static ref ML_SCORE_DISTRIBUTION: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "ritma_ml_score",
            "Distribution of ML scores"
        )
    ).unwrap();

    // System metrics
    pub static ref ACTIVE_NAMESPACES: IntGauge = IntGauge::new(
        "ritma_active_namespaces",
        "Number of active namespaces"
    ).unwrap();

    pub static ref RECEIPTS_SEALED: Counter = Counter::new(
        "ritma_receipts_sealed_total",
        "Total number of receipts sealed"
    ).unwrap();
}

pub fn init_metrics() {
    REGISTRY
        .register(Box::new(TRACES_INGESTED.clone()))
        .unwrap();
    REGISTRY.register(Box::new(NOVEL_EGRESS.clone())).unwrap();
    REGISTRY.register(Box::new(AUTH_FAILURES.clone())).unwrap();
    REGISTRY
        .register(Box::new(WINDOW_PROCESSING_TIME.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(ML_SCORE_DISTRIBUTION.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(ACTIVE_NAMESPACES.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(RECEIPTS_SEALED.clone()))
        .unwrap();
}

pub fn export_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// SLO tracker
pub struct SloTracker {
    pub ml_latency_threshold_ms: u64,
    pub window_tick_interval_secs: u64,
}

impl SloTracker {
    pub fn new() -> Self {
        Self {
            ml_latency_threshold_ms: 100,
            window_tick_interval_secs: 60,
        }
    }

    pub fn check_ml_latency(&self, latency_ms: u64) -> bool {
        latency_ms < self.ml_latency_threshold_ms
    }

    pub fn record_window_processing(&self, duration_secs: f64) {
        WINDOW_PROCESSING_TIME.observe(duration_secs);
    }

    pub fn record_ml_score(&self, score: f64) {
        ML_SCORE_DISTRIBUTION.observe(score);
    }

    pub fn record_trace_ingested(&self) {
        TRACES_INGESTED.inc();
    }

    pub fn record_novel_egress(&self) {
        NOVEL_EGRESS.inc();
    }

    pub fn record_receipt_sealed(&self) {
        RECEIPTS_SEALED.inc();
    }
}

impl Default for SloTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slo_tracker() {
        let tracker = SloTracker::new();
        assert!(tracker.check_ml_latency(50));
        assert!(!tracker.check_ml_latency(150));
    }

    #[test]
    fn test_metrics_export() {
        init_metrics();
        TRACES_INGESTED.inc();
        let metrics = export_metrics();
        assert!(metrics.contains("ritma_traces_ingested_total"));
    }
}
