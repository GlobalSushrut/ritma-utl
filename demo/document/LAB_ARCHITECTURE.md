# Ritma Lab Architecture: Low-Level Technical Specification

> **Purpose**: Detailed technical architecture for implementing the Ritma Lab in Rust.

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         LAB ORCHESTRATOR (Rust)                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
│  │ Topology   │  │ Scenario   │  │   Chaos    │  │ Evidence   │    │
│  │ Manager    │  │ Engine     │  │ Controller │  │ Collector  │    │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘    │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │ Control Plane (gRPC/Unix Socket)
┌─────────────────────────────────┼───────────────────────────────────┐
│                           DATA PLANE                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │   NODE-A     │  │   NODE-B     │  │   NODE-C     │              │
│  │ ┌──────────┐ │  │ ┌──────────┐ │  │ ┌──────────┐ │              │
│  │ │ Workload │ │  │ │ Workload │ │  │ │ Workload │ │              │
│  │ │ + Ritma  │ │  │ │ + Ritma  │ │  │ │ + Ritma  │ │              │
│  │ └──────────┘ │  │ └──────────┘ │  │ └──────────┘ │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │ Evidence Stream
┌─────────────────────────────────▼───────────────────────────────────┐
│                        RITMA AGGREGATOR                              │
│  Window Sealer → Chain Builder → Proofpack Writer → Export          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Crate Structure

```
crates/
├── ritma_lab/              # Main orchestrator
│   ├── src/
│   │   ├── lib.rs
│   │   ├── main.rs         # CLI entry
│   │   ├── orchestrator.rs
│   │   ├── topology.rs
│   │   ├── scenario.rs
│   │   ├── chaos.rs
│   │   ├── traffic.rs
│   │   ├── evidence.rs
│   │   └── container.rs
│   └── Cargo.toml
│
├── ritma_lab_node/         # Node runtime (in container)
│   ├── src/
│   │   ├── main.rs
│   │   ├── workload.rs
│   │   ├── agent.rs
│   │   └── ipc.rs
│   └── Cargo.toml
│
├── ritma_lab_proto/        # Shared protocol
│   ├── src/
│   │   ├── topology.rs
│   │   ├── scenario.rs
│   │   ├── events.rs
│   │   └── control.rs
│   └── Cargo.toml
│
└── ritma_lab_workloads/    # Workload implementations
    └── src/
        ├── web.rs
        ├── api.rs
        ├── db.rs
        └── ml.rs
```

---

## 3. Core Dependencies (Cargo.toml)

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
ciborium = "0.2"
sha2 = "0.10"
blake3 = "1.5"
ed25519-dalek = { version = "2", features = ["rand_core"] }
hyper = { version = "1", features = ["full"] }
bollard = "0.18"           # Docker API
clap = { version = "4", features = ["derive"] }
chrono = "0.4"
uuid = { version = "1", features = ["v4", "v7"] }
tracing = "0.1"
anyhow = "1"
ritma_contract = { path = "../ritma_contract" }
```

---

## 4. Topology Schema (topology.rs)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Topology {
    pub version: String,
    pub metadata: TopologyMetadata,
    pub nodes: Vec<NodeSpec>,
    pub networks: Vec<NetworkSpec>,
    pub aggregator: AggregatorSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSpec {
    pub id: String,
    pub role: NodeRole,
    pub image: Option<String>,
    pub resources: ResourceSpec,
    pub environment: HashMap<String, String>,
    pub ritma: RitmaAgentSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeRole {
    Frontend, Backend, Database, Cache, Queue, MlInference, Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    pub memory: String,  // "256m"
    pub cpu: String,     // "0.5"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RitmaAgentSpec {
    pub enabled: bool,
    pub tier: u8,        // 1=light, 2=medium, 3=full
    pub capture: Vec<CaptureType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaptureType {
    HttpAccessLogs, ApplicationLogs, ProcessExec, ProcessExit,
    FileAccess, NetworkFlows, DnsQueries, DatabaseQueries,
}
```

---

## 5. Scenario Schema (scenario.rs)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub scenario: ScenarioMetadata,
    pub phases: Vec<Phase>,
    pub chaos: Vec<ChaosAction>,
    pub assertions: Vec<Assertion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub name: String,
    pub start: u32,           // Seconds from start
    pub duration: u32,
    pub traffic: Option<TrafficSpec>,
    pub events: Vec<ScriptedEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosAction {
    pub action: ChaosType,
    pub target: String,
    pub start: u32,
    pub duration: Option<u32>,
    pub params: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaosType {
    Latency, PacketLoss, Bandwidth, Down, Restart, CpuPressure, MemoryPressure,
}
```

---

## 6. Event Types (events.rs)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub trace_id: String,
    pub timestamp: Timestamp,
    pub node_id: String,
    pub sequence: u64,
    pub kind: EventKind,
    pub correlation: Option<CorrelationContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventKind {
    ProcExec { pid: i64, ppid: i64, exe: String, exe_hash: String, cmdline: String },
    ProcExit { pid: i64, exit_code: Option<i32>, runtime_ms: u64 },
    FileOpen { path: String, path_hash: String, pid: i64 },
    FileWrite { path: String, bytes: u64, pid: i64 },
    NetConnect { src_ip: String, dst_ip: String, dst_port: u16, pid: i64 },
    HttpRequest { method: String, path: String, status: u16, latency_ms: u32 },
    DbQuery { query_hash: String, query_type: String, latency_ms: u32 },
    InferenceRequest { model_id: String, input_hash: String },
    InferenceResponse { output_hash: String, latency_ms: u32, decision: String },
    GuardrailTrigger { guardrail_id: String, action: String },
    AuthAttempt { user_id: String, success: bool },
    ChaosInjected { chaos_id: String, chaos_type: String },
    Custom { event_type: String, data: HashMap<String, Value> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationContext {
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub user_id: Option<String>,
}
```

---

## 7. Control Messages (control.rs)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlMessage {
    Initialize { node_id: String, role: String, ritma_config: RitmaConfig },
    Start { scenario: String, phase: String },
    Stop { reason: String },
    StartTraffic { traffic_id: String, rps: u32, params: HashMap<String, Value> },
    StopTraffic { traffic_id: String },
    InjectChaos { chaos_id: String, chaos_type: String, params: HashMap<String, Value> },
    RemoveChaos { chaos_id: String },
    TriggerEvent { event_type: String, params: HashMap<String, Value> },
    StatusRequest,
    StatusResponse { state: NodeState, events_generated: u64 },
    Heartbeat { timestamp: i64, sequence: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeState { Initializing, Ready, Running, Stopping, Stopped, Error }
```

---

## 8. Orchestrator Core (orchestrator.rs)

```rust
pub struct LabOrchestrator {
    topology: Option<Topology>,
    scenario: Option<Scenario>,
    nodes: HashMap<String, NodeHandle>,
    container_runtime: Arc<dyn ContainerRuntime>,
    chaos_controller: ChaosController,
    traffic_generator: TrafficGenerator,
    evidence_collector: EvidenceCollector,
    state: Arc<RwLock<LabState>>,
}

impl LabOrchestrator {
    pub async fn load_topology(&mut self, path: &str) -> Result<()>;
    pub async fn load_scenario(&mut self, path: &str) -> Result<()>;
    pub async fn start(&mut self) -> Result<()>;
    pub async fn run_scenario(&mut self) -> Result<()>;
    pub async fn stop(&mut self) -> Result<()>;
    pub async fn export(&self, output: &str) -> Result<String>;
}
```

---

## 9. Container Runtime (container.rs)

```rust
#[async_trait]
pub trait ContainerRuntime: Send + Sync {
    async fn create_network(&self, name: &str, driver: &str) -> Result<String>;
    async fn remove_network(&self, name: &str) -> Result<()>;
    async fn create_container(&self, spec: &NodeSpec) -> Result<String>;
    async fn start_container(&self, id: &str) -> Result<()>;
    async fn stop_container(&self, id: &str) -> Result<()>;
    async fn exec_in_container(&self, id: &str, cmd: &[&str]) -> Result<String>;
    async fn attach_control(&self, id: &str, rx: Receiver<ControlMessage>, tx: Sender<Event>) -> Result<()>;
}

pub struct DockerRuntime { client: Docker }
pub struct PodmanRuntime { client: Podman }
```

---

## 10. Chaos Controller (chaos.rs)

```rust
pub struct ChaosController {
    active: HashMap<String, ChaosHandle>,
    scheduler: tokio::task::JoinHandle<()>,
}

impl ChaosController {
    pub async fn schedule(&mut self, action: ChaosAction) -> Result<()>;
    pub async fn inject(&mut self, target: &str, chaos: ChaosType, params: &HashMap<String, Value>) -> Result<String>;
    pub async fn remove(&mut self, chaos_id: &str) -> Result<()>;
    pub async fn clear_all(&mut self) -> Result<()>;
}

// Chaos implementations
impl ChaosController {
    async fn inject_latency(&self, target: &str, latency_ms: u32, jitter_ms: u32) -> Result<()> {
        // Use tc qdisc netem
        self.exec_in_container(target, &[
            "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
            "delay", &format!("{}ms", latency_ms), &format!("{}ms", jitter_ms)
        ]).await
    }
    
    async fn inject_packet_loss(&self, target: &str, percent: f32) -> Result<()> {
        self.exec_in_container(target, &[
            "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
            "loss", &format!("{}%", percent)
        ]).await
    }
}
```

---

## 11. Traffic Generator (traffic.rs)

```rust
pub struct TrafficGenerator {
    active: HashMap<String, TrafficHandle>,
    rng: StdRng,
}

impl TrafficGenerator {
    pub fn with_seed(seed: u64) -> Self;
    pub async fn start(&mut self, spec: TrafficSpec) -> Result<String>;
    pub async fn stop(&mut self, traffic_id: &str) -> Result<()>;
    pub async fn stop_all(&mut self) -> Result<()>;
}

// Request generation
async fn generate_request(pattern: &TrafficPattern, rng: &mut StdRng) -> Request {
    let request_id = format!("req_{}", Uuid::now_v7());
    let trace_id = format!("trace_{}", Uuid::now_v7());
    
    Request {
        method: pattern.method.clone(),
        path: interpolate_path(&pattern.path, rng),
        headers: vec![
            ("X-Request-ID", request_id),
            ("X-Trace-ID", trace_id),
        ],
        body: generate_body(&pattern.body, rng),
    }
}
```

---

## 12. Evidence Collector (evidence.rs)

```rust
pub struct EvidenceCollector {
    events: Vec<Event>,
    windows: Vec<SealedWindow>,
    chain: Vec<[u8; 32]>,
    current_window_start: i64,
    window_duration: u32,
}

impl EvidenceCollector {
    pub async fn start(&mut self, config: &AggregatorSpec) -> Result<()>;
    pub async fn stop(&mut self) -> Result<()>;
    pub async fn record_event(&mut self, event: Event) -> Result<()>;
    pub async fn seal_window(&mut self) -> Result<SealedWindow>;
    pub async fn export(&self, output: &str) -> Result<String>;
}

#[derive(Debug, Clone, Serialize)]
pub struct SealedWindow {
    pub window_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub event_count: u64,
    pub merkle_root: [u8; 32],
    pub prev_root: [u8; 32],
    pub chain_hash: [u8; 32],
    pub signature: Vec<u8>,
}
```

---

## 13. Node Runtime (ritma_lab_node/main.rs)

```rust
pub struct NodeRuntime {
    node_id: String,
    node_role: String,
    state: NodeState,
    workload: Option<Box<dyn Workload>>,
    agent: Option<RitmaAgent>,
    sequence: u64,
}

impl NodeRuntime {
    pub async fn connect(&mut self, socket: &str) -> Result<()>;
    pub async fn run(&mut self) -> Result<()>;
    async fn handle_control(&mut self, msg: ControlMessage) -> Result<()>;
}

#[async_trait]
pub trait Workload: Send + Sync {
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    async fn start_traffic(&mut self, traffic: &StartTrafficMsg) -> Result<()>;
    async fn stop_traffic(&mut self, traffic_id: &str) -> Result<()>;
}
```

---

## 14. CLI Interface (cli.rs)

```rust
#[derive(Parser)]
#[command(name = "ritma-lab")]
pub enum Cli {
    /// Initialize lab directory
    Init { #[arg(short, long)] path: Option<String> },
    
    /// Start lab
    Up {
        #[arg(short, long)] topology: Option<String>,
        #[arg(short, long)] scenario: Option<String>,
    },
    
    /// Stop lab
    Down { #[arg(short, long)] force: bool },
    
    /// Show status
    Status,
    
    /// Tail logs
    Logs { #[arg(short, long)] node: Option<String> },
    
    /// Run scenario
    Scenario {
        #[command(subcommand)] cmd: ScenarioCmd,
    },
    
    /// Chaos injection
    Chaos {
        #[command(subcommand)] cmd: ChaosCmd,
    },
    
    /// Export proofpack
    Export {
        #[arg(short, long)] output: String,
        #[arg(short, long)] last: Option<String>,
    },
    
    /// Verify proofpack
    Verify { path: String },
}
```

---

## 15. Build & Deployment

### Dockerfile (Node)

```dockerfile
FROM rust:1.75-alpine AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p ritma_lab_node

FROM alpine:3.19
RUN apk add --no-cache tini iproute2
COPY --from=builder /build/target/release/ritma_lab_node /usr/local/bin/
COPY --from=builder /build/target/release/ritma-agent /usr/local/bin/
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/ritma_lab_node"]
```

### Build Script

```bash
#!/bin/bash
set -e

# Build orchestrator
cargo build --release -p ritma_lab

# Build node runtime
cargo build --release -p ritma_lab_node

# Build node image
docker build -t ritma-lab/node:latest -f docker/Dockerfile.node .

# Install CLI
cargo install --path crates/ritma_lab
```

---

## 16. Example Usage

```bash
# Initialize lab
ritma-lab init --path ./my-lab

# Start with scenario
ritma-lab up --topology topology.yaml --scenario ransomware.yaml

# Watch status
ritma-lab status

# Export proofpack
ritma-lab export --output ./proofpack --last 2m

# Verify
ritma-lab verify ./proofpack/proofpack_*.tar.zst
```

---

## 17. Implementation Priority

| Week | Component | Deliverable |
|------|-----------|-------------|
| 1 | ritma_lab_proto | All schemas, events, control messages |
| 2 | ritma_lab (core) | Orchestrator, topology, container runtime |
| 3 | ritma_lab_node | Node runtime, workloads, IPC |
| 4 | Chaos + Traffic | Chaos controller, traffic generator |
| 5 | Evidence + Export | Evidence collector, proofpack export |
| 6 | CLI + Polish | Full CLI, Docker images, docs |

---

*Document Version: 1.0*
