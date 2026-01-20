# Ritma Lab Standard Specification v1.0

> **Purpose**: Create a lightweight, reproducible, production-grade lab environment where fake workloads generate real Ritma evidence. Runs in 1-2 minutes on an old laptop.

---

## Table of Contents

1. [Core Philosophy](#1-core-philosophy)
2. [Architecture Overview](#2-architecture-overview)
3. [Topology Manifest Schema](#3-topology-manifest-schema)
4. [Scenario DSL](#4-scenario-dsl)
5. [Node Specification](#5-node-specification)
6. [Traffic Generation](#6-traffic-generation)
7. [Chaos Injection](#7-chaos-injection)
8. [Evidence Contracts](#8-evidence-contracts)
9. [Rotation & Retention](#9-rotation--retention)
10. [Verify Bundle Format](#10-verify-bundle-format)
11. [Resource Budgets](#11-resource-budgets)
12. [CLI Interface](#12-cli-interface)
13. [Implementation Phases](#13-implementation-phases)

---

## 1. Core Philosophy

### The Separation Rule

| Layer | What's Fake | What's Real |
|-------|-------------|-------------|
| **World Simulator** | HTTP requests, DB queries, auth flows, errors, failures | Nothing |
| **Ritma** | Nothing | Collection, signing, hashing, proofpacks, verification |

**Demo Honesty Standard**: The lab fakes the world, never Ritma. Every signature, hash, and timestamp is cryptographically real.

### Design Principles

1. **Deterministic Reproducibility** (FoundationDB-style)
   - Same scenario + same seed = same traffic pattern
   - Proofs differ only by wall-clock time
   - Every run is debuggable and demo-reliable

2. **Lightweight First**
   - 3 nodes maximum for standard demos
   - Total memory budget: 2GB
   - Total CPU budget: 2 cores
   - Startup to first proof: < 30 seconds

3. **Production-Shaped Primitives**
   - Real request flows with correlation IDs
   - Real failure modes (not random crashes)
   - Real security signals (not fake alerts)

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         LAB ORCHESTRATOR                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │  Topology   │  │  Scenario   │  │   Chaos     │                 │
│  │  Manager    │  │  Engine     │  │  Controller │                 │
│  └─────────────┘  └─────────────┘  └─────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        FAKE NETWORK                                 │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐         │
│  │   NODE-WEB   │───▶│   NODE-API   │───▶│   NODE-DB    │         │
│  │              │    │              │    │              │         │
│  │ ┌──────────┐ │    │ ┌──────────┐ │    │ ┌──────────┐ │         │
│  │ │ workload │ │    │ │ workload │ │    │ │ workload │ │         │
│  │ └──────────┘ │    │ └──────────┘ │    │ └──────────┘ │         │
│  │ ┌──────────┐ │    │ ┌──────────┐ │    │ ┌──────────┐ │         │
│  │ │  ritma   │ │    │ │  ritma   │ │    │ │  ritma   │ │         │
│  │ │  agent   │ │    │ │  agent   │ │    │ │  agent   │ │         │
│  │ └──────────┘ │    │ └──────────┘ │    │ └──────────┘ │         │
│  └──────────────┘    └──────────────┘    └──────────────┘         │
│         │                   │                   │                  │
│         └───────────────────┴───────────────────┘                  │
│                             │                                       │
│                             ▼                                       │
│                    ┌──────────────┐                                │
│                    │   RITMA      │                                │
│                    │  AGGREGATOR  │                                │
│                    └──────────────┘                                │
│                             │                                       │
│                             ▼                                       │
│                    ┌──────────────┐                                │
│                    │  PROOFPACK   │                                │
│                    │   EXPORT     │                                │
│                    └──────────────┘                                │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| **Lab Orchestrator** | Starts/stops nodes, runs scenarios, injects chaos |
| **Node Container** | Runs workload + ritma-agent, isolated filesystem/network |
| **Ritma Agent** | Collects signals, signs events, writes to local stream |
| **Ritma Aggregator** | Seals windows, builds proofpacks, exports bundles |
| **Chaos Controller** | Scripted failures with precise timing and logging |

---

## 3. Topology Manifest Schema

```yaml
# topology.yaml
version: "1.0"
metadata:
  name: "three-tier-demo"
  description: "Web → API → DB with Ritma observability"
  run_id: "${RUN_ID}"           # Auto-generated if not set
  seed: 42                       # For deterministic traffic
  
nodes:
  - id: "node-web"
    role: "frontend"
    image: "ritma-lab/node-web:latest"
    resources:
      memory: "256m"
      cpu: "0.3"
    ports:
      - "8080:80"
    environment:
      NODE_ID: "node-web"
      NODE_ROLE: "frontend"
      UPSTREAM_URL: "http://node-api:3000"
    volumes:
      - "./data/node-web:/data"
    ritma:
      enabled: true
      tier: 1                    # Lightweight collection
      
  - id: "node-api"
    role: "backend"
    image: "ritma-lab/node-api:latest"
    resources:
      memory: "384m"
      cpu: "0.4"
    environment:
      NODE_ID: "node-api"
      NODE_ROLE: "backend"
      DB_URL: "postgres://node-db:5432/demo"
    ritma:
      enabled: true
      tier: 2                    # Medium collection
      
  - id: "node-db"
    role: "database"
    image: "ritma-lab/node-db:latest"
    resources:
      memory: "512m"
      cpu: "0.5"
    environment:
      NODE_ID: "node-db"
      NODE_ROLE: "database"
    ritma:
      enabled: true
      tier: 1

networks:
  - name: "lab-internal"
    driver: "bridge"
    nodes: ["node-web", "node-api", "node-db"]

aggregator:
  window_seconds: 5              # Seal every 5 seconds for demo
  export_path: "./output"
```

### Node Identity Contract

Every node MUST have:

```yaml
identity:
  NODE_ID: string               # Unique identifier (e.g., "node-api-01")
  NODE_ROLE: string             # Role in topology (e.g., "backend")
  keypair: auto                 # Generated at first boot
  sequence_counter: monotonic   # Never resets, survives restarts
```

---

## 4. Scenario DSL

Scenarios define what happens during a lab run. They're deterministic scripts.

```yaml
# scenarios/incident_login_burst.yaml
scenario:
  name: "incident_login_burst"
  description: "Simulates a credential stuffing attack followed by rate limiting"
  duration_seconds: 120
  seed: 42
  
phases:
  - name: "warmup"
    start: 0
    duration: 20
    traffic:
      type: "normal"
      rps: 10
      distribution: "uniform"
      
  - name: "attack"
    start: 20
    duration: 40
    traffic:
      type: "login_burst"
      rps: 100
      distribution: "spike"
      params:
        failure_rate: 0.95       # 95% failed logins
        unique_users: 1000
        target_path: "/api/auth/login"
        
  - name: "rate_limit_active"
    start: 60
    duration: 30
    traffic:
      type: "mixed"
      rps: 50
      params:
        blocked_rate: 0.8        # 80% get 429
        
  - name: "recovery"
    start: 90
    duration: 30
    traffic:
      type: "normal"
      rps: 15

chaos:
  - action: "latency"
    target: "node-api"
    start: 45
    duration: 15
    params:
      latency_ms: 300
      jitter_ms: 50
      
  - action: "restart"
    target: "node-db"
    start: 75
    params:
      downtime_seconds: 5

assertions:
  - type: "event_count"
    filter: "kind=NetConnect"
    min: 1000
    
  - type: "proofpack_sealed"
    count: 24                    # At least 24 windows sealed
    
  - type: "chain_valid"
    description: "All proofpacks form valid chain"
```

### Traffic Types

| Type | Description | Params |
|------|-------------|--------|
| `normal` | Regular user traffic | `rps`, `distribution` |
| `login_burst` | Credential stuffing simulation | `failure_rate`, `unique_users` |
| `api_scan` | API endpoint enumeration | `paths`, `methods` |
| `data_exfil` | Large response patterns | `bytes_per_request` |
| `mixed` | Combination of patterns | `weights` |

---

## 5. Node Specification

### Minimal Node Image Structure

```dockerfile
# Base: Alpine + tini (< 10MB)
FROM alpine:3.19

# Init system
RUN apk add --no-cache tini

# Workload (choose one per node type)
COPY workload /app/workload

# Ritma agent (statically linked)
COPY ritma-agent /usr/local/bin/ritma-agent

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
```

### Entrypoint Script

```bash
#!/bin/sh
set -e

# Initialize node identity
if [ ! -f /data/node_id ]; then
    echo "$NODE_ID" > /data/node_id
    ritma-agent init --node-id "$NODE_ID" --role "$NODE_ROLE"
fi

# Start ritma agent in background
ritma-agent run --tier "${RITMA_TIER:-1}" &
RITMA_PID=$!

# Start workload
/app/workload &
WORKLOAD_PID=$!

# Wait for either to exit
wait -n $RITMA_PID $WORKLOAD_PID
```

### Workload Types

| Role | Workload | Memory | Description |
|------|----------|--------|-------------|
| `frontend` | nginx + lua | 64MB | Reverse proxy, access logs |
| `backend` | Go HTTP server | 128MB | Business logic, structured logs |
| `database` | SQLite + HTTP API | 256MB | Persistent storage, query logs |
| `queue` | In-memory queue | 64MB | Message broker simulation |
| `cache` | In-memory KV | 32MB | Cache hit/miss logs |

---

## 6. Traffic Generation

### Load Generator Design

```yaml
# Built into lab orchestrator
load_generator:
  engine: "internal"             # No external deps (not k6/locust)
  
  request_templates:
    - name: "browse_product"
      method: "GET"
      path: "/api/products/{product_id}"
      headers:
        X-Request-ID: "${request_id}"
        X-Trace-ID: "${trace_id}"
        X-User-ID: "${user_id}"
      weight: 40
      
    - name: "add_to_cart"
      method: "POST"
      path: "/api/cart"
      body:
        product_id: "${product_id}"
        quantity: 1
      headers:
        X-Request-ID: "${request_id}"
        X-Trace-ID: "${trace_id}"
        Authorization: "Bearer ${token}"
      weight: 20
      
    - name: "checkout"
      method: "POST"
      path: "/api/checkout"
      body:
        cart_id: "${cart_id}"
        payment_method: "card"
      weight: 5
      
    - name: "login_attempt"
      method: "POST"
      path: "/api/auth/login"
      body:
        username: "${username}"
        password: "${password}"
      weight: 15
      
    - name: "health_check"
      method: "GET"
      path: "/health"
      weight: 20

  user_simulation:
    session_duration_seconds: 30
    think_time_ms: 500
    concurrent_users: 10
```

### Correlation ID Propagation

Every request flow carries:

```
X-Request-ID: req_abc123        # Unique per request
X-Trace-ID: trace_xyz789        # Spans entire flow
X-User-ID: user_42              # Simulated user
X-Session-ID: sess_def456       # User session
```

These IDs appear in:
- HTTP access logs
- Application logs
- Database query logs
- Ritma trace events

---

## 7. Chaos Injection

### Chaos Controller (Toxiproxy-inspired)

```yaml
chaos_primitives:
  - name: "latency"
    description: "Add delay to network traffic"
    params:
      latency_ms: int
      jitter_ms: int
      direction: "upstream|downstream|both"
      
  - name: "packet_loss"
    description: "Drop percentage of packets"
    params:
      loss_percent: float
      
  - name: "bandwidth"
    description: "Limit throughput"
    params:
      rate_kbps: int
      
  - name: "down"
    description: "Take node offline"
    params:
      duration_seconds: int
      
  - name: "restart"
    description: "Restart node process"
    params:
      downtime_seconds: int
      
  - name: "cpu_pressure"
    description: "Consume CPU cycles"
    params:
      percent: int
      duration_seconds: int
      
  - name: "memory_pressure"
    description: "Consume memory"
    params:
      mb: int
      duration_seconds: int
      
  - name: "disk_slow"
    description: "Slow disk I/O"
    params:
      delay_ms: int
```

### Chaos Log Format

Every chaos action is logged (and captured by Ritma):

```json
{
  "ts": "2024-01-15T10:30:45.123Z",
  "type": "chaos_event",
  "action": "latency",
  "target": "node-api",
  "params": {
    "latency_ms": 300,
    "jitter_ms": 50
  },
  "start_offset_seconds": 45,
  "duration_seconds": 15,
  "chaos_id": "chaos_abc123"
}
```

---

## 8. Evidence Contracts

### Signal Tiers

| Tier | Signals | Overhead | Use Case |
|------|---------|----------|----------|
| **1** | App logs, HTTP access, process lifecycle | ~1% CPU | Default, always-on |
| **2** | + Network flow summaries, file write summaries | ~3% CPU | Enhanced visibility |
| **3** | + eBPF syscall tracing | ~10% CPU | Deep forensics (short bursts) |

### Event Schema (Tier 1)

```json
{
  "trace_id": "te_abc123",
  "ts": "2024-01-15T10:30:45.123456Z",
  "node_id": "node-api",
  "source": "app_log",
  "kind": "HttpRequest",
  "actor": {
    "pid": 1234,
    "uid": 1000,
    "comm": "node-api"
  },
  "target": {
    "method": "POST",
    "path": "/api/cart",
    "status": 200,
    "latency_ms": 45
  },
  "correlation": {
    "request_id": "req_abc123",
    "trace_id": "trace_xyz789",
    "user_id": "user_42"
  }
}
```

### Per-Node Evidence Stream

```
/data/
├── node_id                      # Identity file
├── keypair.json                 # Node signing key
├── sequence                     # Monotonic counter
├── hot/
│   ├── current.jsonl            # Active stream
│   └── current.sig              # Rolling signature
└── sealed/
    ├── window_001.cbor.zst      # Sealed window
    ├── window_001.sig           # Window signature
    └── ...
```

---

## 9. Rotation & Retention

### Window Lifecycle

```
[Hot Stream] ──(seal every N seconds)──▶ [Sealed Window] ──(aggregate)──▶ [Hour Block]
     │                                          │                              │
     ▼                                          ▼                              ▼
  current.jsonl                          window_XXX.cbor.zst              hour_root.cbor
  (append-only)                          (compressed, signed)             (merkle root)
```

### Rotation Rules

```yaml
rotation:
  window_duration_seconds: 5      # Demo: seal every 5s
  max_window_events: 10000        # Or when event count reached
  max_window_bytes: 1048576       # Or when size reached (1MB)
  
retention:
  hot_windows: 12                 # Keep last 12 windows hot
  sealed_hours: 24                # Keep 24 hours of sealed data
  
compression:
  algorithm: "zstd"
  level: 3                        # Fast compression
```

---

## 10. Verify Bundle Format

### Proofpack Structure

```
proofpack_20240115_103000/
├── manifest.json                 # Bundle metadata
├── public_keys/
│   ├── node-web.pub
│   ├── node-api.pub
│   └── node-db.pub
├── chain/
│   ├── hour_00.cbor              # Hour 0 root + chain hash
│   ├── hour_01.cbor
│   └── ...
├── windows/
│   ├── node-web/
│   │   ├── w000.cbor.zst
│   │   ├── w000.sig
│   │   └── ...
│   ├── node-api/
│   │   └── ...
│   └── node-db/
│       └── ...
├── catalog/
│   └── day.cbor.zst              # Daily catalog
└── verify_report.json            # Verification results
```

### Manifest Schema

```json
{
  "version": "1.0",
  "created_at": "2024-01-15T10:30:00Z",
  "run_id": "run_abc123",
  "scenario": "incident_login_burst",
  "seed": 42,
  "duration_seconds": 120,
  "nodes": [
    {
      "node_id": "node-web",
      "role": "frontend",
      "public_key_hash": "sha256:abc123...",
      "window_count": 24,
      "event_count": 15234
    }
  ],
  "chain": {
    "first_root": "sha256:...",
    "last_root": "sha256:...",
    "block_count": 24
  },
  "integrity": {
    "manifest_hash": "sha256:...",
    "signed_by": "aggregator"
  }
}
```

### Verify Command Output

```json
{
  "status": "PASS",
  "verified_at": "2024-01-15T10:32:00Z",
  "checks": [
    {
      "name": "signature_validity",
      "status": "PASS",
      "details": "All 72 signatures valid"
    },
    {
      "name": "chain_continuity",
      "status": "PASS",
      "details": "24 blocks form continuous chain"
    },
    {
      "name": "merkle_roots",
      "status": "PASS",
      "details": "All merkle roots verified"
    },
    {
      "name": "timestamp_ordering",
      "status": "PASS",
      "details": "All timestamps monotonic"
    }
  ],
  "summary": {
    "total_events": 45678,
    "total_windows": 72,
    "time_range": {
      "start": "2024-01-15T10:28:00Z",
      "end": "2024-01-15T10:30:00Z"
    }
  }
}
```

---

## 11. Resource Budgets

### Old Laptop Profile (2GB RAM, 2 cores)

```yaml
resource_profile: "laptop"

total_budget:
  memory: "2048m"
  cpu: "2.0"

allocation:
  orchestrator:
    memory: "128m"
    cpu: "0.2"
    
  aggregator:
    memory: "256m"
    cpu: "0.3"
    
  nodes:
    node-web:
      memory: "256m"
      cpu: "0.3"
    node-api:
      memory: "384m"
      cpu: "0.4"
    node-db:
      memory: "512m"
      cpu: "0.5"
      
  load_generator:
    memory: "128m"
    cpu: "0.2"
    
  buffer:
    memory: "384m"              # For spikes
    cpu: "0.1"

limits:
  max_concurrent_requests: 50
  max_events_per_second: 500
  max_log_buffer_mb: 64
```

### Performance Targets

| Metric | Target | Acceptable |
|--------|--------|------------|
| Startup to first event | < 10s | < 20s |
| Startup to first proof | < 30s | < 60s |
| Event latency (ingest) | < 10ms | < 50ms |
| Window seal time | < 500ms | < 2s |
| Memory growth/hour | < 50MB | < 100MB |
| CPU idle (no traffic) | < 5% | < 10% |

---

## 12. CLI Interface

### Command Structure

```bash
# Lab lifecycle
ritma lab init                    # Create lab directory structure
ritma lab up [--scenario NAME]    # Start lab with optional scenario
ritma lab down                    # Stop lab gracefully
ritma lab status                  # Show running nodes and stats
ritma lab logs [NODE]             # Tail logs from node(s)

# Scenario management
ritma lab scenario list           # List available scenarios
ritma lab scenario run NAME       # Run scenario on active lab
ritma lab scenario stop           # Stop current scenario

# Chaos injection
ritma lab chaos inject PRIMITIVE TARGET [PARAMS]
ritma lab chaos list              # Show active chaos
ritma lab chaos clear             # Remove all chaos

# Evidence export
ritma lab export [--last DURATION] [--output PATH]
ritma lab verify PROOFPACK        # Verify exported bundle

# Tracing
ritma lab trace --request ID      # Trace request across nodes
ritma lab trace --user ID         # Trace user session
ritma lab trace --time RANGE      # Trace time window

# Development
ritma lab build                   # Build node images
ritma lab clean                   # Remove all lab data
```

### Example Session

```bash
# Start a 2-minute demo
$ ritma lab up --scenario incident_login_burst

Starting Ritma Lab...
  ✓ Topology: three-tier-demo
  ✓ Scenario: incident_login_burst (seed=42)
  ✓ Duration: 120 seconds

Nodes:
  ✓ node-web    [frontend]   256MB  0.3 CPU
  ✓ node-api    [backend]    384MB  0.4 CPU
  ✓ node-db     [database]   512MB  0.5 CPU

Lab running. Press Ctrl+C to stop early.

Phase: warmup (0-20s)     ████████████████████ 100%
Phase: attack (20-60s)    ████████████████████ 100%
Phase: rate_limit (60-90s) ████████████████████ 100%
Phase: recovery (90-120s)  ████████████████████ 100%

Lab completed.
  Events captured: 45,678
  Windows sealed: 72
  Chain valid: ✓

$ ritma lab export --output ./demo_proofpack

Exporting proofpack...
  ✓ Collected 72 windows from 3 nodes
  ✓ Built chain with 24 hour blocks
  ✓ Generated manifest
  ✓ Signed bundle

Exported: ./demo_proofpack/proofpack_20240115_103000.tar.zst (2.3 MB)

$ ritma lab verify ./demo_proofpack/proofpack_20240115_103000.tar.zst

Verifying proofpack...
  ✓ Manifest integrity
  ✓ Public key authenticity
  ✓ 72 window signatures
  ✓ 24 block chain continuity
  ✓ Merkle root consistency
  ✓ Timestamp ordering

VERIFICATION PASSED

Summary:
  Run ID: run_abc123
  Scenario: incident_login_burst
  Duration: 120 seconds
  Events: 45,678
  Nodes: 3
```

---

## 13. Implementation Phases

### Phase 1: Foundation (Week 1)

**Goal**: Minimal working lab with 1 node

- [ ] Lab orchestrator skeleton (Rust)
- [ ] Single node container (Alpine + tini + mock workload)
- [ ] Basic ritma-agent integration
- [ ] `ritma lab up/down/status` commands
- [ ] Simple traffic generator (10 RPS)

**Deliverable**: `ritma lab up` starts 1 node, generates traffic, produces events

### Phase 2: Multi-Node (Week 2)

**Goal**: 3-node topology with real data flow

- [ ] Topology manifest parser
- [ ] Docker Compose generation
- [ ] Inter-node networking
- [ ] Correlation ID propagation
- [ ] `ritma lab logs` command

**Deliverable**: Web → API → DB flow with correlated events

### Phase 3: Scenarios (Week 3)

**Goal**: Scripted scenarios with chaos

- [ ] Scenario DSL parser
- [ ] Phase-based traffic patterns
- [ ] Chaos controller (latency, restart)
- [ ] Chaos logging
- [ ] Built-in scenarios (3-5)

**Deliverable**: `ritma lab up --scenario incident_login_burst`

### Phase 4: Evidence & Export (Week 4)

**Goal**: Production-grade proofpacks

- [ ] Window sealing pipeline
- [ ] Chain building
- [ ] Proofpack export
- [ ] Verify command
- [ ] Manifest generation

**Deliverable**: `ritma lab export && ritma lab verify`

### Phase 5: Polish (Week 5)

**Goal**: Demo-ready experience

- [ ] Resource profiling and tuning
- [ ] Progress indicators
- [ ] Error handling
- [ ] Documentation
- [ ] 5 polished scenarios

**Deliverable**: Investor-ready 2-minute demo

---

## Appendix A: Built-in Scenarios

### 1. `baseline_traffic`
Normal operations, no incidents. Establishes "what normal looks like."

### 2. `incident_login_burst`
Credential stuffing attack → rate limiting → recovery.

### 3. `incident_db_failover`
Database restart → connection errors → automatic recovery.

### 4. `incident_latency_spike`
Network latency injection → timeout cascade → SLA breach.

### 5. `incident_data_breach`
Suspicious API access patterns → large data extraction → detection.

---

## Appendix B: Fake Data Patterns

### User Simulation

```yaml
users:
  pool_size: 100
  patterns:
    - type: "normal_user"
      weight: 70
      behavior:
        session_length: "5-30 minutes"
        actions_per_session: "3-15"
        
    - type: "power_user"
      weight: 20
      behavior:
        session_length: "30-120 minutes"
        actions_per_session: "20-100"
        
    - type: "bot"
      weight: 10
      behavior:
        session_length: "1-5 minutes"
        actions_per_session: "50-200"
        request_interval: "10-50ms"
```

### Product Catalog

```yaml
products:
  count: 50
  categories: ["electronics", "clothing", "books", "home"]
  price_range: [9.99, 999.99]
  
  access_pattern:
    popular: 10%                 # 10% of products get 80% of views
    long_tail: 90%
```

---

## Appendix C: Security Signals (Safe but Believable)

| Signal | Pattern | Ritma Capture |
|--------|---------|---------------|
| Login failures | Burst of 401s from same IP | `kind=HttpRequest, status=401` |
| Path probing | Requests to `/admin`, `/wp-login.php` | `kind=HttpRequest, path=...` |
| Rate limiting | 429 responses | `kind=HttpRequest, status=429` |
| Token issues | 401 with expired JWT | `kind=HttpRequest, auth_error=expired` |
| Large responses | Unusual response sizes | `kind=HttpRequest, bytes_out>1MB` |
| Slow queries | DB queries > 1s | `kind=DbQuery, latency_ms>1000` |

---

## Appendix D: References

1. **FoundationDB Simulation Testing**: https://apple.github.io/foundationdb/testing.html
2. **Toxiproxy**: https://github.com/Shopify/toxiproxy
3. **OpenTelemetry Demo**: https://opentelemetry.io/docs/demo/
4. **Google Microservices Demo**: https://github.com/GoogleCloudPlatform/microservices-demo
5. **Chaos Engineering Principles**: https://principlesofchaos.org/
6. **Deterministic Simulation Testing**: https://antithesis.com/resources/deterministic_simulation_testing/

---

*Document Version: 1.0*
*Last Updated: 2024-01-15*
*Author: Ritma Team*
