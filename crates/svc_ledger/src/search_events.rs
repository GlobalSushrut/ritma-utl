// Hyper-Secure Search Event Logging
// Audit trail for all search queries with DID-based authentication and rate limiting

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// Search event capturing who searched for what
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEvent {
    /// Unique query ID
    pub query_id: String,

    /// Caller DID (from mTLS cert)
    pub caller_did: String,

    /// Search query string
    pub query: String,

    /// Search filters applied
    pub filters: HashMap<String, String>,

    /// Timestamp
    pub timestamp: u64,

    /// Number of results returned
    pub results_count: usize,

    /// SVC policy ID that authorized this search
    pub svc_policy_id: Option<String>,

    /// Purpose/justification for search
    pub purpose: String,

    /// Signature over search event
    pub signature: String,

    /// Schema version
    #[serde(default)]
    pub schema_version: u32,

    /// Hash of previous search event (chain)
    #[serde(default)]
    pub prev_hash: Option<String>,

    /// Hash of this search event
    #[serde(default)]
    pub event_hash: String,
}

impl SearchEvent {
    /// Compute event hash (excluding event_hash and signature)
    pub fn compute_hash(&self) -> String {
        let mut hashable = self.clone();
        hashable.event_hash = String::new();
        hashable.signature = String::new();

        let json = serde_json::to_string(&hashable).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Search query with security context
#[derive(Debug, Clone)]
pub struct SecureSearchQuery {
    /// Caller DID
    pub caller_did: String,

    /// Query string
    pub query: String,

    /// Filters
    pub filters: HashMap<String, String>,

    /// Purpose
    pub purpose: String,

    /// Tenant ID (for isolation)
    pub tenant_id: Option<String>,
}

/// Search result with SVC correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Result ID
    pub id: String,

    /// Result type (decision, burn, control, etc.)
    pub result_type: String,

    /// Result data
    pub data: serde_json::Value,

    /// SVC commit ID
    pub svc_commit_id: Option<String>,

    /// Infrastructure version ID
    pub infra_version_id: Option<String>,

    /// Tenant ID
    pub tenant_id: Option<String>,
}

/// Rate limiter for search queries
pub struct SearchRateLimiter {
    limits: HashMap<String, RateLimit>,
}

#[derive(Debug, Clone)]
struct RateLimit {
    count: u32,
    window_start: u64,
    max_per_window: u32,
    window_secs: u64,
}

impl SearchRateLimiter {
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
        }
    }

    /// Check if DID is within rate limit
    pub fn check_limit(
        &mut self,
        did: &str,
        max_per_window: u32,
        window_secs: u64,
    ) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let limit = self.limits.entry(did.to_string()).or_insert(RateLimit {
            count: 0,
            window_start: now,
            max_per_window,
            window_secs,
        });

        // Reset window if expired
        if now - limit.window_start >= limit.window_secs {
            limit.count = 0;
            limit.window_start = now;
        }

        // Check limit
        if limit.count >= limit.max_per_window {
            return Err(format!(
                "Rate limit exceeded: {} queries in {} seconds",
                limit.count, limit.window_secs
            ));
        }

        limit.count += 1;
        Ok(())
    }
}

impl Default for SearchRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Hyper-secure search gateway
pub struct SecureSearchGateway {
    event_log_path: String,
    rate_limiter: SearchRateLimiter,
    default_rate_limit: u32,
    default_window_secs: u64,
}

impl SecureSearchGateway {
    pub fn new(event_log_path: String) -> Self {
        Self {
            event_log_path,
            rate_limiter: SearchRateLimiter::new(),
            default_rate_limit: 100, // 100 queries per window
            default_window_secs: 60, // 60 seconds
        }
    }

    /// Execute a secure search query
    pub fn search(&mut self, query: SecureSearchQuery) -> Result<Vec<SearchResult>, String> {
        // 1. Rate limiting
        self.rate_limiter.check_limit(
            &query.caller_did,
            self.default_rate_limit,
            self.default_window_secs,
        )?;

        // 2. Validate purpose
        if query.purpose.is_empty() {
            return Err("Search purpose is required".to_string());
        }

        // 3. Tenant isolation check
        if let Some(ref tenant) = query.tenant_id {
            if !query.filters.contains_key("tenant_id") {
                return Err("Tenant filter required for tenant-scoped search".to_string());
            }
            if query.filters.get("tenant_id") != Some(tenant) {
                return Err("Tenant filter mismatch".to_string());
            }
        }

        // 4. Execute search (stub - would call actual search backend)
        let results = self.execute_search_backend(&query)?;

        // 5. Log search event
        self.log_search_event(&query, results.len())?;

        Ok(results)
    }

    /// Execute actual search (stub)
    fn execute_search_backend(
        &self,
        _query: &SecureSearchQuery,
    ) -> Result<Vec<SearchResult>, String> {
        // Stub: In production, this would:
        // - Query Elasticsearch/OpenSearch
        // - Apply tenant filters
        // - Redact sensitive fields
        // - Correlate with SVC commits

        // For now, return empty results
        Ok(Vec::new())
    }

    /// Log search event to audit trail
    fn log_search_event(
        &self,
        query: &SecureSearchQuery,
        results_count: usize,
    ) -> Result<(), String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let query_id = format!("search_{}_{}", query.caller_did, timestamp);

        // Get previous event hash
        let prev_hash = self
            .read_last_event_hash()
            .map_err(|e| format!("Failed to read last event hash: {e}"))?;

        let mut event = SearchEvent {
            query_id,
            caller_did: query.caller_did.clone(),
            query: query.query.clone(),
            filters: query.filters.clone(),
            timestamp,
            results_count,
            svc_policy_id: None, // TODO: Get from policy engine
            purpose: query.purpose.clone(),
            signature: String::new(), // TODO: Sign with gateway key
            schema_version: 1,
            prev_hash,
            event_hash: String::new(),
        };

        // Compute event hash
        event.event_hash = event.compute_hash();

        // Sign event (stub)
        event.signature = self.sign_event(&event)?;

        // Write to log
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.event_log_path)
            .map_err(|e| format!("Failed to open search log: {e}"))?;

        let line =
            serde_json::to_string(&event).map_err(|e| format!("Failed to serialize event: {e}"))?;
        file.write_all(line.as_bytes())
            .map_err(|e| format!("Failed to write event: {e}"))?;
        file.write_all(b"\n")
            .map_err(|e| format!("Failed to write newline: {e}"))?;
        file.flush().map_err(|e| format!("Failed to flush: {e}"))?;

        Ok(())
    }

    /// Read last event hash for chaining
    fn read_last_event_hash(&self) -> std::io::Result<Option<String>> {
        let file = match std::fs::File::open(&self.event_log_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        let reader = BufReader::new(file);
        let mut last_hash: Option<String> = None;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(event) = serde_json::from_str::<SearchEvent>(&line) {
                last_hash = Some(event.event_hash);
            }
        }

        Ok(last_hash)
    }

    /// Sign search event (stub)
    fn sign_event(&self, event: &SearchEvent) -> Result<String, String> {
        // Stub: In production, use actual cryptographic signing
        let mut hasher = Sha256::new();
        hasher.update(event.event_hash.as_bytes());
        hasher.update(b"gateway_key");
        Ok(format!("sig_{}", hex::encode(hasher.finalize())))
    }

    /// Verify search event chain integrity
    pub fn verify_chain(&self) -> Result<(), String> {
        let file = std::fs::File::open(&self.event_log_path)
            .map_err(|e| format!("Failed to open log: {e}"))?;

        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Failed to read line: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }

            let event: SearchEvent =
                serde_json::from_str(&line).map_err(|e| format!("Failed to parse event: {e}"))?;
            events.push(event);
        }

        if events.is_empty() {
            return Ok(());
        }

        // Verify first event has no prev_hash
        if events[0].prev_hash.is_some() {
            return Err("First event should not have prev_hash".to_string());
        }

        // Verify each event's hash
        for event in &events {
            let computed = event.compute_hash();
            if computed != event.event_hash {
                return Err(format!("Event hash mismatch for {}", event.query_id));
            }
        }

        // Verify chain linkage
        for i in 1..events.len() {
            let prev_hash = &events[i - 1].event_hash;
            let current_prev = events[i]
                .prev_hash
                .as_ref()
                .ok_or_else(|| format!("Event {i} missing prev_hash"))?;

            if prev_hash != current_prev {
                return Err(format!("Chain broken at event {i}"));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_enforces_limits() {
        let mut limiter = SearchRateLimiter::new();

        // First 3 queries should succeed
        for _ in 0..3 {
            assert!(limiter.check_limit("did:ritma:user:alice", 3, 60).is_ok());
        }

        // 4th query should fail
        assert!(limiter.check_limit("did:ritma:user:alice", 3, 60).is_err());
    }

    #[test]
    fn search_gateway_logs_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("search_events.jsonl");
        let mut gateway = SecureSearchGateway::new(log_path.to_string_lossy().to_string());

        let query = SecureSearchQuery {
            caller_did: "did:ritma:user:alice".to_string(),
            query: "framework:SOC2".to_string(),
            filters: {
                let mut f = HashMap::new();
                f.insert("framework".to_string(), "SOC2".to_string());
                f
            },
            purpose: "Audit review".to_string(),
            tenant_id: None,
        };

        let result = gateway.search(query);
        assert!(result.is_ok());

        // Verify event was logged
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn search_gateway_verifies_chain() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("search_events.jsonl");
        let mut gateway = SecureSearchGateway::new(log_path.to_string_lossy().to_string());

        // Log multiple events
        for i in 0..3 {
            let query = SecureSearchQuery {
                caller_did: "did:ritma:user:alice".to_string(),
                query: format!("query_{}", i),
                filters: HashMap::new(),
                purpose: "Test".to_string(),
                tenant_id: None,
            };
            gateway.search(query).unwrap();

            // Small delay to ensure unique timestamps
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Verify chain
        let result = gateway.verify_chain();
        if let Err(e) = &result {
            eprintln!("Chain verification failed: {}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn search_requires_purpose() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("search_events.jsonl");
        let mut gateway = SecureSearchGateway::new(log_path.to_string_lossy().to_string());

        let query = SecureSearchQuery {
            caller_did: "did:ritma:user:alice".to_string(),
            query: "test".to_string(),
            filters: HashMap::new(),
            purpose: String::new(), // Empty purpose
            tenant_id: None,
        };

        assert!(gateway.search(query).is_err());
    }

    #[test]
    fn search_enforces_tenant_isolation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("search_events.jsonl");
        let mut gateway = SecureSearchGateway::new(log_path.to_string_lossy().to_string());

        let query = SecureSearchQuery {
            caller_did: "did:ritma:user:alice".to_string(),
            query: "test".to_string(),
            filters: HashMap::new(), // Missing tenant filter
            purpose: "Test".to_string(),
            tenant_id: Some("tenant_a".to_string()),
        };

        assert!(gateway.search(query).is_err());
    }
}
