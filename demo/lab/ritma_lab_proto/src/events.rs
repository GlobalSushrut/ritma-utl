use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Timestamp {
    pub secs: i64,
    pub nanos: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        Self {
            secs: now.as_secs() as i64,
            nanos: now.subsec_nanos(),
        }
    }

    pub fn to_rfc3339(&self) -> String {
        chrono::DateTime::from_timestamp(self.secs, self.nanos)
            .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
            .unwrap_or_default()
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub trace_id: String,
    pub timestamp: Timestamp,
    pub node_id: String,
    pub sequence: u64,
    pub kind: EventKind,
    #[serde(default)]
    pub correlation: Option<CorrelationContext>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl Event {
    pub fn new(node_id: String, sequence: u64, kind: EventKind) -> Self {
        Self {
            trace_id: format!("te_{}", uuid::Uuid::now_v7()),
            timestamp: Timestamp::now(),
            node_id,
            sequence,
            kind,
            correlation: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_correlation(mut self, ctx: CorrelationContext) -> Self {
        self.correlation = Some(ctx);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationContext {
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    ProcExec(ProcExecEvent),
    ProcExit(ProcExitEvent),
    FileOpen(FileOpenEvent),
    FileWrite(FileWriteEvent),
    FileDelete(FileDeleteEvent),
    NetConnect(NetConnectEvent),
    NetClose(NetCloseEvent),
    DnsQuery(DnsQueryEvent),
    HttpRequest(HttpRequestEvent),
    HttpResponse(HttpResponseEvent),
    DbQuery(DbQueryEvent),
    InferenceRequest(InferenceRequestEvent),
    InferenceResponse(InferenceResponseEvent),
    GuardrailTrigger(GuardrailTriggerEvent),
    AuthAttempt(AuthAttemptEvent),
    PrivilegeChange(PrivilegeChangeEvent),
    PolicyViolation(PolicyViolationEvent),
    ChaosInjected(ChaosInjectedEvent),
    ChaosRemoved(ChaosRemovedEvent),
    Custom(CustomEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcExecEvent {
    pub pid: i64,
    pub ppid: i64,
    pub uid: i64,
    pub gid: i64,
    pub exe: String,
    pub exe_hash: String,
    pub cmdline: String,
    pub cmdline_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcExitEvent {
    pub pid: i64,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub runtime_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOpenEvent {
    pub path: String,
    pub path_hash: String,
    pub flags: u32,
    pub pid: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWriteEvent {
    pub path: String,
    pub path_hash: String,
    pub bytes: u64,
    pub pid: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDeleteEvent {
    pub path: String,
    pub path_hash: String,
    pub pid: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConnectEvent {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub pid: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetCloseEvent {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryEvent {
    pub query_name: String,
    pub query_type: String,
    pub response_ip: Option<String>,
    pub response_time_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestEvent {
    pub method: String,
    pub path: String,
    pub host: String,
    pub user_agent: Option<String>,
    pub content_length: Option<u64>,
    pub headers_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseEvent {
    pub status: u16,
    pub content_length: Option<u64>,
    pub latency_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbQueryEvent {
    pub query_hash: String,
    pub query_type: String,
    pub table: Option<String>,
    pub rows_affected: Option<u64>,
    pub latency_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequestEvent {
    pub model_id: String,
    pub model_version: String,
    pub input_hash: String,
    pub input_token_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponseEvent {
    pub output_hash: String,
    pub output_token_count: Option<u32>,
    pub latency_ms: u32,
    pub confidence_score: Option<f32>,
    pub decision_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailTriggerEvent {
    pub guardrail_id: String,
    pub guardrail_type: String,
    pub action_taken: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAttemptEvent {
    pub user_id: String,
    pub auth_method: String,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub ip_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeChangeEvent {
    pub pid: i64,
    pub old_uid: i64,
    pub new_uid: i64,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolationEvent {
    pub policy_id: String,
    pub violation_type: String,
    pub action: String,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosInjectedEvent {
    pub chaos_id: String,
    pub chaos_type: String,
    pub target: String,
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosRemovedEvent {
    pub chaos_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomEvent {
    pub event_type: String,
    pub data: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization() {
        let event = Event::new(
            "node-a".to_string(),
            1,
            EventKind::HttpRequest(HttpRequestEvent {
                method: "GET".to_string(),
                path: "/api/health".to_string(),
                host: "localhost".to_string(),
                user_agent: Some("test".to_string()),
                content_length: None,
                headers_hash: "abc123".to_string(),
            }),
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("http_request"));
        assert!(json.contains("node-a"));
    }
}
