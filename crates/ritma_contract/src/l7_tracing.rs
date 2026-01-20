//! L7/HTTP Tracing Module
//!
//! Provides HTTP request/response parsing and tracing for application-layer visibility.
//! This module captures HTTP traffic from socket read/write operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HTTP Method
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,
    Unknown(String),
}

impl HttpMethod {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => HttpMethod::GET,
            "POST" => HttpMethod::POST,
            "PUT" => HttpMethod::PUT,
            "DELETE" => HttpMethod::DELETE,
            "PATCH" => HttpMethod::PATCH,
            "HEAD" => HttpMethod::HEAD,
            "OPTIONS" => HttpMethod::OPTIONS,
            "TRACE" => HttpMethod::TRACE,
            "CONNECT" => HttpMethod::CONNECT,
            other => HttpMethod::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::TRACE => "TRACE",
            HttpMethod::CONNECT => "CONNECT",
            HttpMethod::Unknown(s) => s.as_str(),
        }
    }
}

/// Parsed HTTP Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub host: Option<String>,
    pub content_length: Option<usize>,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub authorization_present: bool,
    pub body_preview: Option<String>,
}

/// Parsed HTTP Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub content_length: Option<usize>,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub body_preview: Option<String>,
}

/// HTTP Transaction (request + response pair)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTransaction {
    pub id: String,
    pub timestamp: String,
    pub pid: i64,
    pub fd: i32,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub request: Option<HttpRequest>,
    pub response: Option<HttpResponse>,
    pub latency_ms: Option<u64>,
}

/// L7 Protocol Detection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum L7Protocol {
    HTTP,
    HTTPS,
    HTTP2,
    GRPC,
    WebSocket,
    DNS,
    MySQL,
    PostgreSQL,
    Redis,
    MongoDB,
    Kafka,
    Unknown,
}

impl L7Protocol {
    /// Detect protocol from payload bytes
    pub fn detect(payload: &[u8]) -> Self {
        if payload.is_empty() {
            return L7Protocol::Unknown;
        }

        // HTTP/1.x detection
        if payload.len() >= 4 {
            let start = &payload[..std::cmp::min(16, payload.len())];
            if start.starts_with(b"GET ")
                || start.starts_with(b"POST ")
                || start.starts_with(b"PUT ")
                || start.starts_with(b"DELETE ")
                || start.starts_with(b"HEAD ")
                || start.starts_with(b"OPTIONS ")
                || start.starts_with(b"PATCH ")
                || start.starts_with(b"CONNECT ")
                || start.starts_with(b"TRACE ")
                || start.starts_with(b"HTTP/")
            {
                return L7Protocol::HTTP;
            }
        }

        // HTTP/2 preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        if payload.len() >= 24 && payload.starts_with(b"PRI * HTTP/2.0") {
            return L7Protocol::HTTP2;
        }

        // TLS/HTTPS detection (TLS handshake starts with 0x16 0x03)
        if payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03 {
            return L7Protocol::HTTPS;
        }

        // DNS detection (already handled elsewhere, but include for completeness)
        if payload.len() >= 12 {
            let flags = ((payload[2] as u16) << 8) | (payload[3] as u16);
            let qdcount = ((payload[4] as u16) << 8) | (payload[5] as u16);
            let qr = (flags >> 15) & 1;
            if qdcount > 0 && qdcount <= 4 && (qr == 0 || qr == 1) {
                // Could be DNS
                return L7Protocol::DNS;
            }
        }

        // MySQL detection (greeting packet starts with protocol version)
        if payload.len() >= 5 && payload[4] == 0x0a {
            // MySQL protocol version 10
            return L7Protocol::MySQL;
        }

        // PostgreSQL detection (startup message)
        if payload.len() >= 8 {
            let len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            if len > 8 && len < 1024 {
                let proto = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                if proto == 196608 || proto == 80877103 {
                    // 3.0 or SSL request
                    return L7Protocol::PostgreSQL;
                }
            }
        }

        // Redis detection (RESP protocol)
        if payload.len() >= 1 {
            match payload[0] {
                b'+' | b'-' | b':' | b'$' | b'*' => {
                    // RESP simple string, error, integer, bulk string, array
                    if payload.iter().any(|&b| b == b'\r') {
                        return L7Protocol::Redis;
                    }
                }
                _ => {}
            }
        }

        // gRPC detection (HTTP/2 with application/grpc content-type)
        // This is typically detected after HTTP/2 parsing

        L7Protocol::Unknown
    }
}

/// HTTP Parser for extracting request/response from raw bytes
pub struct HttpParser {
    max_header_size: usize,
    max_body_preview: usize,
}

impl Default for HttpParser {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpParser {
    pub fn new() -> Self {
        Self {
            max_header_size: 8192,
            max_body_preview: 256,
        }
    }

    pub fn with_limits(max_header_size: usize, max_body_preview: usize) -> Self {
        Self {
            max_header_size,
            max_body_preview,
        }
    }

    /// Parse HTTP request from bytes
    pub fn parse_request(&self, data: &[u8]) -> Option<HttpRequest> {
        let data = &data[..std::cmp::min(data.len(), self.max_header_size)];
        let text = std::str::from_utf8(data).ok()?;

        // Find end of headers
        let header_end = text.find("\r\n\r\n").or_else(|| text.find("\n\n"))?;
        let header_section = &text[..header_end];

        let mut lines = header_section.lines();

        // Parse request line: METHOD URI VERSION
        let request_line = lines.next()?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let method = HttpMethod::from_str(parts[0]);
        let uri = parts[1].to_string();
        let version = parts.get(2).unwrap_or(&"HTTP/1.0").to_string();

        // Parse headers
        let mut headers = HashMap::new();
        let mut host = None;
        let mut content_length = None;
        let mut content_type = None;
        let mut user_agent = None;
        let mut authorization_present = false;

        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                match key.as_str() {
                    "host" => host = Some(value.clone()),
                    "content-length" => content_length = value.parse().ok(),
                    "content-type" => content_type = Some(value.clone()),
                    "user-agent" => user_agent = Some(value.clone()),
                    "authorization" | "proxy-authorization" => authorization_present = true,
                    _ => {}
                }

                headers.insert(key, value);
            }
        }

        // Extract body preview if present
        let body_start = header_end
            + if text[header_end..].starts_with("\r\n\r\n") {
                4
            } else {
                2
            };
        let body_preview = if body_start < text.len() {
            let body = &text[body_start..];
            let preview_len = std::cmp::min(body.len(), self.max_body_preview);
            Some(body[..preview_len].to_string())
        } else {
            None
        };

        Some(HttpRequest {
            method,
            uri,
            version,
            headers,
            host,
            content_length,
            content_type,
            user_agent,
            authorization_present,
            body_preview,
        })
    }

    /// Parse HTTP response from bytes
    pub fn parse_response(&self, data: &[u8]) -> Option<HttpResponse> {
        let data = &data[..std::cmp::min(data.len(), self.max_header_size)];
        let text = std::str::from_utf8(data).ok()?;

        // Find end of headers
        let header_end = text.find("\r\n\r\n").or_else(|| text.find("\n\n"))?;
        let header_section = &text[..header_end];

        let mut lines = header_section.lines();

        // Parse status line: VERSION STATUS_CODE STATUS_TEXT
        let status_line = lines.next()?;
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return None;
        }

        let version = parts[0].to_string();
        let status_code: u16 = parts[1].parse().ok()?;
        let status_text = parts.get(2).unwrap_or(&"").to_string();

        // Parse headers
        let mut headers = HashMap::new();
        let mut content_length = None;
        let mut content_type = None;
        let mut server = None;

        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                match key.as_str() {
                    "content-length" => content_length = value.parse().ok(),
                    "content-type" => content_type = Some(value.clone()),
                    "server" => server = Some(value.clone()),
                    _ => {}
                }

                headers.insert(key, value);
            }
        }

        // Extract body preview if present
        let body_start = header_end
            + if text[header_end..].starts_with("\r\n\r\n") {
                4
            } else {
                2
            };
        let body_preview = if body_start < text.len() {
            let body = &text[body_start..];
            let preview_len = std::cmp::min(body.len(), self.max_body_preview);
            Some(body[..preview_len].to_string())
        } else {
            None
        };

        Some(HttpResponse {
            version,
            status_code,
            status_text,
            headers,
            content_length,
            content_type,
            server,
            body_preview,
        })
    }

    /// Check if data looks like an HTTP request
    pub fn is_http_request(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        data.starts_with(b"GET ")
            || data.starts_with(b"POST ")
            || data.starts_with(b"PUT ")
            || data.starts_with(b"DELETE ")
            || data.starts_with(b"HEAD ")
            || data.starts_with(b"OPTIONS ")
            || data.starts_with(b"PATCH ")
            || data.starts_with(b"CONNECT ")
            || data.starts_with(b"TRACE ")
    }

    /// Check if data looks like an HTTP response
    pub fn is_http_response(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        data.starts_with(b"HTTP/")
    }
}

/// L7 Event for trace storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7Event {
    pub trace_id: String,
    pub timestamp: String,
    pub pid: i64,
    pub fd: i32,
    pub protocol: L7Protocol,
    pub direction: L7Direction,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub request: Option<HttpRequest>,
    pub response: Option<HttpResponse>,
    pub latency_ms: Option<u64>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum L7Direction {
    Request,
    Response,
    Unknown,
}

/// L7 Transaction Tracker
/// Correlates requests with responses using (pid, fd) as key
pub struct L7TransactionTracker {
    pending: HashMap<(i64, i32), PendingTransaction>,
    max_pending: usize,
    ttl_ms: u64,
}

struct PendingTransaction {
    request: HttpRequest,
    request_time: std::time::Instant,
    src_addr: Option<String>,
    dst_addr: Option<String>,
}

impl Default for L7TransactionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl L7TransactionTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            max_pending: 10000,
            ttl_ms: 30000,
        }
    }

    pub fn with_limits(max_pending: usize, ttl_ms: u64) -> Self {
        Self {
            pending: HashMap::new(),
            max_pending,
            ttl_ms,
        }
    }

    /// Record a request, returns None (waiting for response)
    pub fn record_request(
        &mut self,
        pid: i64,
        fd: i32,
        request: HttpRequest,
        src_addr: Option<String>,
        dst_addr: Option<String>,
    ) {
        // Cleanup old entries
        self.cleanup();

        if self.pending.len() >= self.max_pending {
            return;
        }

        self.pending.insert(
            (pid, fd),
            PendingTransaction {
                request,
                request_time: std::time::Instant::now(),
                src_addr,
                dst_addr,
            },
        );
    }

    /// Record a response, returns completed transaction if request was pending
    pub fn record_response(
        &mut self,
        pid: i64,
        fd: i32,
        response: HttpResponse,
    ) -> Option<HttpTransaction> {
        let pending = self.pending.remove(&(pid, fd))?;
        let latency_ms = pending.request_time.elapsed().as_millis() as u64;

        Some(HttpTransaction {
            id: format!("http_{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            pid,
            fd,
            src_addr: pending.src_addr,
            dst_addr: pending.dst_addr,
            request: Some(pending.request),
            response: Some(response),
            latency_ms: Some(latency_ms),
        })
    }

    fn cleanup(&mut self) {
        let ttl = std::time::Duration::from_millis(self.ttl_ms);
        let now = std::time::Instant::now();
        self.pending
            .retain(|_, v| now.duration_since(v.request_time) < ttl);
    }
}

/// Sensitive data detection for HTTP payloads
pub struct SensitiveDataDetector {
    patterns: Vec<SensitivePattern>,
}

struct SensitivePattern {
    name: &'static str,
    pattern: &'static str,
}

impl Default for SensitiveDataDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SensitiveDataDetector {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                SensitivePattern {
                    name: "credit_card",
                    pattern: "credit_card_pattern",
                },
                SensitivePattern {
                    name: "ssn",
                    pattern: "ssn_pattern",
                },
                SensitivePattern {
                    name: "email",
                    pattern: "email_pattern",
                },
                SensitivePattern {
                    name: "api_key",
                    pattern: "api_key_pattern",
                },
                SensitivePattern {
                    name: "password",
                    pattern: "password_pattern",
                },
                SensitivePattern {
                    name: "bearer_token",
                    pattern: "bearer_token_pattern",
                },
            ],
        }
    }

    /// Check if text contains sensitive data patterns
    pub fn contains_sensitive(&self, text: &str) -> Vec<&'static str> {
        let mut found = Vec::new();
        let text_lower = text.to_lowercase();

        for pattern in &self.patterns {
            // Simple substring check for common patterns
            // In production, use regex crate for proper pattern matching
            match pattern.name {
                "credit_card" => {
                    // Look for 16 digit sequences
                    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
                    if digits.len() >= 16 {
                        found.push(pattern.name);
                    }
                }
                "ssn" => {
                    if text.contains('-') {
                        let parts: Vec<&str> = text.split('-').collect();
                        if parts.len() >= 3 {
                            let valid = parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()));
                            if valid {
                                found.push(pattern.name);
                            }
                        }
                    }
                }
                "email" => {
                    if text.contains('@') && text.contains('.') {
                        found.push(pattern.name);
                    }
                }
                "api_key" => {
                    if text_lower.contains("api_key")
                        || text_lower.contains("apikey")
                        || text_lower.contains("access_token")
                    {
                        found.push(pattern.name);
                    }
                }
                "password" => {
                    if text_lower.contains("password=")
                        || text_lower.contains("passwd=")
                        || text_lower.contains("pwd=")
                    {
                        found.push(pattern.name);
                    }
                }
                "bearer_token" => {
                    if text.contains("Bearer ") {
                        found.push(pattern.name);
                    }
                }
                _ => {}
            }
        }

        found
    }

    /// Redact sensitive data from text
    pub fn redact(&self, text: &str) -> String {
        let mut result = text.to_string();

        // Redact Bearer tokens
        if result.contains("Bearer ") {
            if let Some(start) = result.find("Bearer ") {
                let token_start = start + 7;
                let token_end = result[token_start..]
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    .map(|i| token_start + i)
                    .unwrap_or(result.len());
                result.replace_range(token_start..token_end, "[REDACTED]");
            }
        }

        // Redact Authorization header values
        if let Some(start) = result.to_lowercase().find("authorization:") {
            let value_start = start + 14;
            let value_end = result[value_start..]
                .find('\n')
                .map(|i| value_start + i)
                .unwrap_or(result.len());
            let prefix_end = result[value_start..value_end]
                .find(' ')
                .map(|i| value_start + i + 1)
                .unwrap_or(value_start);
            result.replace_range(prefix_end..value_end, "[REDACTED]");
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_parsing() {
        assert_eq!(HttpMethod::from_str("GET"), HttpMethod::GET);
        assert_eq!(HttpMethod::from_str("post"), HttpMethod::POST);
        assert_eq!(
            HttpMethod::from_str("UNKNOWN"),
            HttpMethod::Unknown("UNKNOWN".to_string())
        );
    }

    #[test]
    fn test_l7_protocol_detection() {
        assert_eq!(
            L7Protocol::detect(b"GET /api/v1 HTTP/1.1\r\n"),
            L7Protocol::HTTP
        );
        assert_eq!(
            L7Protocol::detect(b"POST /data HTTP/1.1\r\n"),
            L7Protocol::HTTP
        );
        assert_eq!(L7Protocol::detect(b"HTTP/1.1 200 OK\r\n"), L7Protocol::HTTP);
        assert_eq!(L7Protocol::detect(&[0x16, 0x03, 0x01]), L7Protocol::HTTPS);
        assert_eq!(L7Protocol::detect(b""), L7Protocol::Unknown);
    }

    #[test]
    fn test_http_request_parsing() {
        let parser = HttpParser::new();
        let request = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nContent-Length: 0\r\n\r\n";

        let parsed = parser.parse_request(request).unwrap();
        assert_eq!(parsed.method, HttpMethod::GET);
        assert_eq!(parsed.uri, "/api/users");
        assert_eq!(parsed.host, Some("example.com".to_string()));
        assert_eq!(parsed.user_agent, Some("test".to_string()));
    }

    #[test]
    fn test_http_response_parsing() {
        let parser = HttpParser::new();
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"status\":\"ok\"}";

        let parsed = parser.parse_response(response).unwrap();
        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.status_text, "OK");
        assert_eq!(parsed.content_type, Some("application/json".to_string()));
    }

    #[test]
    fn test_sensitive_data_detection() {
        let detector = SensitiveDataDetector::new();

        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig";
        let found = detector.contains_sensitive(text);
        assert!(found.contains(&"bearer_token"));

        let text2 = "email=user@example.com&password=secret123";
        let found2 = detector.contains_sensitive(text2);
        assert!(found2.contains(&"email"));
        assert!(found2.contains(&"password"));
    }

    #[test]
    fn test_transaction_tracker() {
        let mut tracker = L7TransactionTracker::new();
        let parser = HttpParser::new();

        let request = parser
            .parse_request(b"GET /api HTTP/1.1\r\nHost: test\r\n\r\n")
            .unwrap();
        tracker.record_request(
            123,
            4,
            request,
            Some("127.0.0.1:5000".to_string()),
            Some("10.0.0.1:80".to_string()),
        );

        let response = parser.parse_response(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        let txn = tracker.record_response(123, 4, response).unwrap();

        assert_eq!(txn.pid, 123);
        assert!(txn.request.is_some());
        assert!(txn.response.is_some());
        assert!(txn.latency_ms.is_some());
    }
}
