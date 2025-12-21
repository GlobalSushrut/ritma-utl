//! Middleware Adapters for BAR
//!
//! This crate provides adapters that convert various middleware formats
//! (HTTP, OTEL, gateway logs) into canonical DecisionEvent format for BAR processing.
//!
//! # Architecture
//!
//! - HTTP Adapter: Converts HTTP request/response data into DecisionEvents
//! - OTEL Adapter: Converts OpenTelemetry spans/traces into DecisionEvents
//! - Gateway Adapter: Converts API gateway logs into DecisionEvents
//!
//! All adapters implement the `MiddlewareAdapter` trait for consistent processing.

use common_models::{DecisionEvent, Actor, ActorType, Subject, Action, Context, EnvStamp, RedactionInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdapterError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Adapter not available: {0}")]
    AdapterUnavailable(String),
}

/// Core trait for middleware adapters
pub trait MiddlewareAdapter: Send + Sync {
    /// Convert adapter-specific input to canonical DecisionEvent
    fn adapt(&self, input: &[u8]) -> Result<DecisionEvent, AdapterError>;
    
    /// Get adapter name
    fn adapter_name(&self) -> &str;
    
    /// Check if adapter is available
    fn is_available(&self) -> bool;
}

/// HTTP request/response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestData {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body_hash: Option<String>,
    pub remote_addr: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
}

/// HTTP adapter configuration
#[derive(Debug, Clone)]
pub struct HttpAdapterConfig {
    pub namespace_id: String,
    pub service_name: String,
    pub environment: String,
    pub build_hash: String,
    pub region: String,
    pub redact_headers: Vec<String>,
    pub redact_query_params: Vec<String>,
}

impl Default for HttpAdapterConfig {
    fn default() -> Self {
        Self {
            namespace_id: "ns://unknown/dev/app/svc".to_string(),
            service_name: "unknown".to_string(),
            environment: "dev".to_string(),
            build_hash: "unknown".to_string(),
            region: "unknown".to_string(),
            redact_headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "x-api-key".to_string(),
            ],
            redact_query_params: vec![
                "token".to_string(),
                "api_key".to_string(),
            ],
        }
    }
}

/// HTTP adapter
pub struct HttpAdapter {
    config: HttpAdapterConfig,
}

impl HttpAdapter {
    pub fn new(config: HttpAdapterConfig) -> Self {
        Self { config }
    }
    
    /// Hash a string value for privacy
    fn hash_value(value: &str) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(value.as_bytes());
        hex::encode(hash)
    }
    
    /// Extract actor from HTTP request
    fn extract_actor(&self, req: &HttpRequestData) -> Actor {
        // Try to extract user ID from headers or use IP hash
        let id_hash = if let Some(auth) = req.headers.get("authorization") {
            Self::hash_value(auth)
        } else if let Some(user_id) = req.headers.get("x-user-id") {
            Self::hash_value(user_id)
        } else if let Some(ip) = &req.remote_addr {
            Self::hash_value(ip)
        } else {
            "anonymous".to_string()
        };
        
        Actor {
            r#type: ActorType::User,
            id_hash,
            roles: vec![],
        }
    }
    
    /// Extract subject from HTTP request
    fn extract_subject(&self, req: &HttpRequestData) -> Subject {
        // Subject is the resource being accessed (path)
        Subject {
            r#type: "http_resource".to_string(),
            id_hash: Self::hash_value(&req.path),
        }
    }
    
    /// Extract action from HTTP request
    fn extract_action(&self, req: &HttpRequestData) -> Action {
        // Action is the HTTP method + any body hash
        Action {
            name: req.method.clone(),
            params_hash: req.body_hash.clone(),
        }
    }
    
    /// Extract context from HTTP request
    fn extract_context(&self, req: &HttpRequestData) -> Context {
        Context {
            request_id: req.request_id.clone(),
            trace_id: req.trace_id.clone(),
            ip_hash: req.remote_addr.as_ref().map(|ip| Self::hash_value(ip)),
            user_agent_hash: req.user_agent.as_ref().map(|ua| Self::hash_value(ua)),
        }
    }
    
    /// Create redaction info
    fn create_redaction(&self, req: &HttpRequestData) -> RedactionInfo {
        let mut applied = Vec::new();
        
        // Check for redacted headers
        for header in &self.config.redact_headers {
            if req.headers.contains_key(header) {
                applied.push(format!("header:{}", header));
            }
        }
        
        // Check for redacted query params
        for param in &self.config.redact_query_params {
            if req.query_params.contains_key(param) {
                applied.push(format!("query:{}", param));
            }
        }
        
        let has_redactions = !applied.is_empty();
        RedactionInfo {
            applied,
            strategy: if has_redactions {
                Some("privacy".to_string())
            } else {
                None
            },
        }
    }
}

impl MiddlewareAdapter for HttpAdapter {
    fn adapt(&self, input: &[u8]) -> Result<DecisionEvent, AdapterError> {
        // Parse input as JSON
        let req: HttpRequestData = serde_json::from_slice(input)
            .map_err(|e| AdapterError::SerializationError(e.to_string()))?;
        
        // Generate event ID
        let event_id = format!("http_evt_{}", uuid::Uuid::new_v4());
        
        // Get current timestamp
        let ts = chrono::Utc::now().to_rfc3339();
        
        Ok(DecisionEvent {
            event_id,
            namespace_id: self.config.namespace_id.clone(),
            ts,
            event_type: format!("HTTP_{}", req.method),
            actor: self.extract_actor(&req),
            subject: self.extract_subject(&req),
            action: self.extract_action(&req),
            context: self.extract_context(&req),
            env_stamp: EnvStamp {
                env: self.config.environment.clone(),
                service: self.config.service_name.clone(),
                build_hash: self.config.build_hash.clone(),
                region: self.config.region.clone(),
                trust_flags: vec![],
            },
            redaction: self.create_redaction(&req),
            stage_trace: vec![],
        })
    }
    
    fn adapter_name(&self) -> &str {
        "http"
    }
    
    fn is_available(&self) -> bool {
        true
    }
}

/// OTEL span data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelSpanData {
    pub span_id: String,
    pub trace_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: String,
    pub start_time: String,
    pub end_time: String,
    pub attributes: HashMap<String, serde_json::Value>,
    pub events: Vec<HashMap<String, serde_json::Value>>,
}

/// OTEL adapter
pub struct OtelAdapter {
    namespace_id: String,
    service_name: String,
}

impl OtelAdapter {
    pub fn new(namespace_id: String, service_name: String) -> Self {
        Self {
            namespace_id,
            service_name,
        }
    }
    
    fn hash_value(value: &str) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(value.as_bytes());
        hex::encode(hash)
    }
}

impl MiddlewareAdapter for OtelAdapter {
    fn adapt(&self, input: &[u8]) -> Result<DecisionEvent, AdapterError> {
        let span: OtelSpanData = serde_json::from_slice(input)
            .map_err(|e| AdapterError::SerializationError(e.to_string()))?;
        
        // Extract actor from span attributes (e.g., user.id, http.user_agent)
        let actor_id = span.attributes.get("user.id")
            .or_else(|| span.attributes.get("http.client_ip"))
            .and_then(|v| v.as_str())
            .map(Self::hash_value)
            .unwrap_or_else(|| "anonymous".to_string());
        
        // Extract subject from span name or target
        let subject_id = span.attributes.get("http.target")
            .or_else(|| span.attributes.get("db.statement"))
            .and_then(|v| v.as_str())
            .map(Self::hash_value)
            .unwrap_or_else(|| Self::hash_value(&span.name));
        
        Ok(DecisionEvent {
            event_id: format!("otel_evt_{}", span.span_id),
            namespace_id: self.namespace_id.clone(),
            ts: span.start_time.clone(),
            event_type: format!("OTEL_{}", span.kind),
            actor: Actor {
                r#type: ActorType::Service,
                id_hash: actor_id,
                roles: vec![],
            },
            subject: Subject {
                r#type: "otel_span".to_string(),
                id_hash: subject_id,
            },
            action: Action {
                name: span.name.clone(),
                params_hash: None,
            },
            context: Context {
                request_id: None,
                trace_id: Some(span.trace_id.clone()),
                ip_hash: None,
                user_agent_hash: None,
            },
            env_stamp: EnvStamp {
                env: "prod".to_string(),
                service: self.service_name.clone(),
                build_hash: "unknown".to_string(),
                region: "unknown".to_string(),
                trust_flags: vec![],
            },
            redaction: RedactionInfo {
                applied: vec![],
                strategy: None,
            },
            stage_trace: vec![],
        })
    }
    
    fn adapter_name(&self) -> &str {
        "otel"
    }
    
    fn is_available(&self) -> bool {
        true
    }
}

/// Gateway log data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayLogData {
    pub request_id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub latency_ms: u64,
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub api_key_hash: Option<String>,
    pub upstream_service: Option<String>,
}

/// Gateway adapter
pub struct GatewayAdapter {
    namespace_id: String,
}

impl GatewayAdapter {
    pub fn new(namespace_id: String) -> Self {
        Self { namespace_id }
    }
    
    fn hash_value(value: &str) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(value.as_bytes());
        hex::encode(hash)
    }
}

impl MiddlewareAdapter for GatewayAdapter {
    fn adapt(&self, input: &[u8]) -> Result<DecisionEvent, AdapterError> {
        let log: GatewayLogData = serde_json::from_slice(input)
            .map_err(|e| AdapterError::SerializationError(e.to_string()))?;
        
        // Actor is the API client
        let actor_id = log.api_key_hash.clone()
            .unwrap_or_else(|| Self::hash_value(&log.client_ip));
        
        Ok(DecisionEvent {
            event_id: format!("gw_evt_{}", log.request_id),
            namespace_id: self.namespace_id.clone(),
            ts: log.timestamp.clone(),
            event_type: format!("GATEWAY_{}", log.method),
            actor: Actor {
                r#type: ActorType::Service,
                id_hash: actor_id,
                roles: vec![],
            },
            subject: Subject {
                r#type: "gateway_route".to_string(),
                id_hash: Self::hash_value(&log.path),
            },
            action: Action {
                name: log.method.clone(),
                params_hash: None,
            },
            context: Context {
                request_id: Some(log.request_id.clone()),
                trace_id: None,
                ip_hash: Some(Self::hash_value(&log.client_ip)),
                user_agent_hash: log.user_agent.as_ref().map(|ua| Self::hash_value(ua)),
            },
            env_stamp: EnvStamp {
                env: "prod".to_string(),
                service: log.upstream_service.unwrap_or_else(|| "gateway".to_string()),
                build_hash: "unknown".to_string(),
                region: "unknown".to_string(),
                trust_flags: vec![],
            },
            redaction: RedactionInfo {
                applied: if log.api_key_hash.is_some() {
                    vec!["api_key".to_string()]
                } else {
                    vec![]
                },
                strategy: None,
            },
            stage_trace: vec![],
        })
    }
    
    fn adapter_name(&self) -> &str {
        "gateway"
    }
    
    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn http_adapter_converts_request() {
        let config = HttpAdapterConfig {
            namespace_id: "ns://test/prod/app/svc".to_string(),
            service_name: "test_svc".to_string(),
            environment: "prod".to_string(),
            build_hash: "build123".to_string(),
            region: "us-east-1".to_string(),
            ..Default::default()
        };
        
        let adapter = HttpAdapter::new(config);
        
        let req = HttpRequestData {
            method: "GET".to_string(),
            path: "/api/users/123".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("x-user-id".to_string(), "user_456".to_string());
                h
            },
            query_params: HashMap::new(),
            body_hash: None,
            remote_addr: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            request_id: Some("req_789".to_string()),
            trace_id: Some("trace_abc".to_string()),
        };
        
        let input = serde_json::to_vec(&req).unwrap();
        let event = adapter.adapt(&input).expect("adapt");
        
        assert_eq!(event.namespace_id, "ns://test/prod/app/svc");
        assert_eq!(event.event_type, "HTTP_GET");
        assert_eq!(event.subject.r#type, "http_resource");
        assert_eq!(event.action.name, "GET");
        assert_eq!(event.context.request_id, Some("req_789".to_string()));
    }
    
    #[test]
    fn otel_adapter_converts_span() {
        let adapter = OtelAdapter::new(
            "ns://test/prod/app/svc".to_string(),
            "test_svc".to_string(),
        );
        
        let span = OtelSpanData {
            span_id: "span_123".to_string(),
            trace_id: "trace_456".to_string(),
            parent_span_id: None,
            name: "GET /api/users".to_string(),
            kind: "SERVER".to_string(),
            start_time: "2025-12-18T00:00:00Z".to_string(),
            end_time: "2025-12-18T00:00:01Z".to_string(),
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert("user.id".to_string(), serde_json::json!("user_789"));
                attrs
            },
            events: vec![],
        };
        
        let input = serde_json::to_vec(&span).unwrap();
        let event = adapter.adapt(&input).expect("adapt");
        
        assert_eq!(event.namespace_id, "ns://test/prod/app/svc");
        assert_eq!(event.event_type, "OTEL_SERVER");
        assert_eq!(event.context.trace_id, Some("trace_456".to_string()));
    }
    
    #[test]
    fn gateway_adapter_converts_log() {
        let adapter = GatewayAdapter::new("ns://test/prod/app/svc".to_string());
        
        let log = GatewayLogData {
            request_id: "req_123".to_string(),
            timestamp: "2025-12-18T00:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/orders".to_string(),
            status_code: 201,
            latency_ms: 150,
            client_ip: "10.0.0.1".to_string(),
            user_agent: Some("curl/7.68.0".to_string()),
            api_key_hash: Some("key_hash_456".to_string()),
            upstream_service: Some("orders_svc".to_string()),
        };
        
        let input = serde_json::to_vec(&log).unwrap();
        let event = adapter.adapt(&input).expect("adapt");
        
        assert_eq!(event.namespace_id, "ns://test/prod/app/svc");
        assert_eq!(event.event_type, "GATEWAY_POST");
        assert_eq!(event.subject.r#type, "gateway_route");
        assert_eq!(event.action.name, "POST");
        assert!(!event.redaction.applied.is_empty());
    }
}
