use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Initialize(InitializeMsg),
    Start(StartMsg),
    Stop(StopMsg),
    Shutdown(ShutdownMsg),
    StartTraffic(StartTrafficMsg),
    StopTraffic(StopTrafficMsg),
    InjectChaos(InjectChaosMsg),
    RemoveChaos(RemoveChaosMsg),
    TriggerEvent(TriggerEventMsg),
    StatusRequest(StatusRequestMsg),
    StatusResponse(StatusResponseMsg),
    Heartbeat(HeartbeatMsg),
    HeartbeatAck(HeartbeatAckMsg),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeMsg {
    pub node_id: String,
    pub role: String,
    pub config: HashMap<String, serde_json::Value>,
    pub ritma_config: RitmaConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RitmaConfig {
    pub tier: u8,
    pub capture: Vec<String>,
    pub window_seconds: u32,
    pub aggregator_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartMsg {
    pub scenario_name: String,
    pub phase_name: String,
    pub start_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopMsg {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownMsg {
    pub graceful: bool,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartTrafficMsg {
    pub traffic_id: String,
    pub traffic_type: String,
    pub rps: u32,
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopTrafficMsg {
    pub traffic_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectChaosMsg {
    pub chaos_id: String,
    pub chaos_type: String,
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveChaosMsg {
    pub chaos_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerEventMsg {
    pub event_type: String,
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequestMsg {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponseMsg {
    pub node_id: String,
    pub state: NodeState,
    pub uptime_ms: u64,
    pub events_generated: u64,
    pub active_traffic: Vec<String>,
    pub active_chaos: Vec<String>,
    pub resource_usage: ResourceUsage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    Initializing,
    Ready,
    Running,
    Stopping,
    Stopped,
    Error,
}

impl Default for NodeState {
    fn default() -> Self {
        NodeState::Initializing
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub memory_limit: u64,
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            cpu_percent: 0.0,
            memory_bytes: 0,
            memory_limit: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMsg {
    pub timestamp: i64,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAckMsg {
    pub timestamp: i64,
    pub sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_message_serialization() {
        let msg = ControlMessage::Initialize(InitializeMsg {
            node_id: "node-a".to_string(),
            role: "frontend".to_string(),
            config: HashMap::new(),
            ritma_config: RitmaConfig {
                tier: 1,
                capture: vec!["http_access_logs".to_string()],
                window_seconds: 5,
                aggregator_endpoint: "unix:///var/run/ritma/aggregator.sock".to_string(),
            },
        });

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("initialize"));
        assert!(json.contains("node-a"));
    }
}
