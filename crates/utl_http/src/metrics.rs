// Simple metrics for utl_http in Prometheus text format
// Using atomic counters to avoid heavyweight prometheus dependency

use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// Simple global metrics using atomics
pub struct SimpleMetrics {
    pub http_requests_total: AtomicU64,
    pub mtls_connections_success: AtomicU64,
    pub mtls_connections_failure: AtomicU64,
    pub mtls_did_extractions_success: AtomicU64,
    pub mtls_did_extractions_failure: AtomicU64,
    pub utld_requests_success: AtomicU64,
    pub utld_requests_failure: AtomicU64,
    pub search_queries_total: AtomicU64,
    pub decisions_allow: AtomicU64,
    pub decisions_deny: AtomicU64,
    pub decisions_other: AtomicU64,
    // Labeled metrics stored in a mutex-protected map
    pub labeled_counters: Mutex<HashMap<String, u64>>,
}

impl SimpleMetrics {
    pub fn new() -> Self {
        Self {
            http_requests_total: AtomicU64::new(0),
            mtls_connections_success: AtomicU64::new(0),
            mtls_connections_failure: AtomicU64::new(0),
            mtls_did_extractions_success: AtomicU64::new(0),
            mtls_did_extractions_failure: AtomicU64::new(0),
            utld_requests_success: AtomicU64::new(0),
            utld_requests_failure: AtomicU64::new(0),
            search_queries_total: AtomicU64::new(0),
            decisions_allow: AtomicU64::new(0),
            decisions_deny: AtomicU64::new(0),
            decisions_other: AtomicU64::new(0),
            labeled_counters: Mutex::new(HashMap::new()),
        }
    }

    pub fn inc_labeled(&self, key: String) {
        if let Ok(mut map) = self.labeled_counters.lock() {
            *map.entry(key).or_insert(0) += 1;
        }
    }
}

static METRICS: OnceLock<SimpleMetrics> = OnceLock::new();

fn metrics() -> &'static SimpleMetrics {
    METRICS.get_or_init(SimpleMetrics::new)
}

/// Encode all metrics in Prometheus text format
pub fn encode_metrics() -> Result<String, Box<dyn std::error::Error>> {
    let mut output = String::new();
    
    // HTTP metrics
    output.push_str("# HELP ritma_http_requests_total Total number of HTTP requests\n");
    output.push_str("# TYPE ritma_http_requests_total counter\n");
    output.push_str(&format!("ritma_http_requests_total {}\n", 
        metrics().http_requests_total.load(Ordering::Relaxed)));
    
    // mTLS metrics
    output.push_str("# HELP ritma_mtls_connections_total Total mTLS connections\n");
    output.push_str("# TYPE ritma_mtls_connections_total counter\n");
    output.push_str(&format!("ritma_mtls_connections_total{{result=\"success\"}} {}\n",
        metrics().mtls_connections_success.load(Ordering::Relaxed)));
    output.push_str(&format!("ritma_mtls_connections_total{{result=\"failure\"}} {}\n",
        metrics().mtls_connections_failure.load(Ordering::Relaxed)));
    
    output.push_str("# HELP ritma_mtls_did_extractions_total DID extractions from client certs\n");
    output.push_str("# TYPE ritma_mtls_did_extractions_total counter\n");
    output.push_str(&format!("ritma_mtls_did_extractions_total{{result=\"success\"}} {}\n",
        metrics().mtls_did_extractions_success.load(Ordering::Relaxed)));
    output.push_str(&format!("ritma_mtls_did_extractions_total{{result=\"failure\"}} {}\n",
        metrics().mtls_did_extractions_failure.load(Ordering::Relaxed)));
    
    // UTLD metrics
    output.push_str("# HELP ritma_utld_requests_total Requests to utld\n");
    output.push_str("# TYPE ritma_utld_requests_total counter\n");
    output.push_str(&format!("ritma_utld_requests_total{{result=\"success\"}} {}\n",
        metrics().utld_requests_success.load(Ordering::Relaxed)));
    output.push_str(&format!("ritma_utld_requests_total{{result=\"failure\"}} {}\n",
        metrics().utld_requests_failure.load(Ordering::Relaxed)));
    
    // Decision metrics
    output.push_str("# HELP ritma_decisions_total Policy decisions\n");
    output.push_str("# TYPE ritma_decisions_total counter\n");
    output.push_str(&format!("ritma_decisions_total{{decision=\"allow\"}} {}\n",
        metrics().decisions_allow.load(Ordering::Relaxed)));
    output.push_str(&format!("ritma_decisions_total{{decision=\"deny\"}} {}\n",
        metrics().decisions_deny.load(Ordering::Relaxed)));
    output.push_str(&format!("ritma_decisions_total{{decision=\"other\"}} {}\n",
        metrics().decisions_other.load(Ordering::Relaxed)));
    
    // Search metrics
    output.push_str("# HELP ritma_search_queries_total Search queries\n");
    output.push_str("# TYPE ritma_search_queries_total counter\n");
    output.push_str(&format!("ritma_search_queries_total {}\n",
        metrics().search_queries_total.load(Ordering::Relaxed)));
    
    // Labeled counters
    if let Ok(map) = metrics().labeled_counters.lock() {
        for (key, value) in map.iter() {
            output.push_str(&format!("{} {}\n", key, value));
        }
    }
    
    Ok(output)
}

/// Record an HTTP request
pub fn record_http_request(_method: &str, _path: &str, _status: u16, _duration_secs: f64) {
    metrics().http_requests_total.fetch_add(1, Ordering::Relaxed);
}

/// Record a policy decision
pub fn record_decision(decision: &str, _tenant: &str, _policy: &str) {
    match decision {
        "allow" => metrics().decisions_allow.fetch_add(1, Ordering::Relaxed),
        "deny" => metrics().decisions_deny.fetch_add(1, Ordering::Relaxed),
        _ => metrics().decisions_other.fetch_add(1, Ordering::Relaxed),
    };
}

/// Record an mTLS connection
pub fn record_mtls_connection(_did: Option<&str>, success: bool) {
    if success {
        metrics().mtls_connections_success.fetch_add(1, Ordering::Relaxed);
    } else {
        metrics().mtls_connections_failure.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record DID extraction from client cert
pub fn record_did_extraction(success: bool) {
    if success {
        metrics().mtls_did_extractions_success.fetch_add(1, Ordering::Relaxed);
    } else {
        metrics().mtls_did_extractions_failure.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a request to utld
pub fn record_utld_request(_request_type: &str, success: bool, _duration_secs: f64) {
    if success {
        metrics().utld_requests_success.fetch_add(1, Ordering::Relaxed);
    } else {
        metrics().utld_requests_failure.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a search query
pub fn record_search_query(_index: &str, _tenant: &str, _result_count: usize) {
    metrics().search_queries_total.fetch_add(1, Ordering::Relaxed);
}

/// Update active connection count (stored as labeled counter)
pub fn set_active_connections(protocol: &str, count: i64) {
    let key = format!("ritma_active_connections{{protocol=\"{}\"}} ", protocol);
    if let Ok(mut map) = metrics().labeled_counters.lock() {
        map.insert(key, count as u64);
    }
}

/// Increment an arbitrary labeled counter by 1.
///
/// The key should already be a full Prometheus metric line prefix, including
/// metric name and labels, and a trailing space before the value, e.g.:
/// `ritma_securitykit_slo_events_total{component="connector",outcome="ok"} `
pub fn inc_labeled_counter(key: &str) {
    metrics().inc_labeled(key.to_string());
}
