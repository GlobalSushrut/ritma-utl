# Ritma SDK - Developer Guide

Build forensic security applications on top of Ritma's court-grade evidence platform.

## Installation

### Option 1: Debian Package (apt)
```bash
# Add Ritma repository
curl -fsSL https://get.ritma.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/ritma.gpg
echo "deb [signed-by=/usr/share/keyrings/ritma.gpg] https://apt.ritma.io stable main" | sudo tee /etc/apt/sources.list.d/ritma.list

# Install
sudo apt update
sudo apt install ritma
```

### Option 2: Cargo (from source)
```bash
# Clone and build
git clone https://github.com/ritma-io/ritma
cd ritma
cargo build --release

# Install
sudo ./install.sh
```

### Option 3: Quick Install Script
```bash
curl -sSL https://get.ritma.io | sudo bash
```

## Quick Start

### CLI Commands
```bash
# Capture events for 60 seconds
ritma capture --duration 60 --output ./evidence

# Verify a proofpack
ritma verify ./evidence/proofpack

# Export sealed windows
ritma export-window --namespace my-app --output ./export

# Start interactive demo
ritma demo --scenario ransomware
```

### Start Sidecar Service
```bash
sudo systemctl start ritma-sidecar
sudo systemctl enable ritma-sidecar

# Check status
sudo systemctl status ritma-sidecar
journalctl -u ritma-sidecar -f
```

## SDK: Building on Ritma

### Rust Crates

Add Ritma crates to your `Cargo.toml`:

```toml
[dependencies]
# Core types and models
common_models = { git = "https://github.com/ritma-io/ritma", package = "common_models" }

# Storage and indexing
index_db = { git = "https://github.com/ritma-io/ritma", package = "index_db" }
ritma_contract = { git = "https://github.com/ritma-io/ritma", package = "ritma_contract" }

# BAR pipeline (seal and prove)
bar_orchestrator = { git = "https://github.com/ritma-io/ritma", package = "bar_orchestrator" }

# Forensic ML
forensic_ml = { git = "https://github.com/ritma-io/ritma", package = "forensic_ml" }

# Security interfaces
security_interfaces = { git = "https://github.com/ritma-io/ritma", package = "security_interfaces" }
```

### Example: Custom Event Recording

```rust
use common_models::{TraceEvent, EventPayload, WindowRange};
use index_db::IndexDb;
use bar_orchestrator::Orchestrator;
use security_interfaces::PipelineOrchestrator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize storage
    let index = IndexDb::open("/var/lib/ritma/index.db")?;
    let orchestrator = Orchestrator::new(index.clone())?;
    
    // Record a custom event
    let event = TraceEvent {
        trace_id: uuid::Uuid::new_v4().to_string(),
        timestamp_ns: chrono::Utc::now().timestamp_nanos() as u64,
        namespace_id: "my-app".to_string(),
        event_type: "custom_audit".to_string(),
        payload: EventPayload::Custom {
            data: serde_json::json!({
                "user_id": "user_123",
                "action": "login",
                "ip": "192.168.1.100"
            })
        },
        ..Default::default()
    };
    
    index.insert_trace_event_from_model(&event)?;
    
    // Seal window (triggers full BAR pipeline)
    let window = WindowRange {
        start_ts: chrono::Utc::now().timestamp() - 300,
        end_ts: chrono::Utc::now().timestamp(),
    };
    
    let proof = orchestrator.run_window("my-app", &window)?;
    println!("Sealed window: {:?}", proof.merkle_root);
    
    Ok(())
}
```

### Example: Forensic ML Analysis

```rust
use forensic_ml::{ForensicMLEngine, MLNotary};
use common_models::WindowRange;

fn analyze_window(namespace: &str, window: &WindowRange) -> Result<(), Box<dyn std::error::Error>> {
    let engine = ForensicMLEngine::new();
    let notary = MLNotary::new("my-key-id");
    
    // Run 4-layer forensic analysis
    let result = engine.analyze(namespace, window)?;
    
    println!("Forensic Score: {:.2}", result.final_score);
    println!("Verdict: {:?}", result.verdict);
    println!("Explanation: {}", result.human_explanation);
    
    // Notarize the result (cryptographic attestation)
    let notarized = notary.notarize(&result)?;
    println!("Notary Hash: {}", notarized.notary_hash);
    
    Ok(())
}
```

### Example: Using the Demo Lab

```rust
use ritma_lab::{LabOrchestrator, ForensicEvidenceCollector};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize lab with forensic evidence collection
    let collector = ForensicEvidenceCollector::new(
        PathBuf::from("./my-lab"),
        "my-node",
        "my-namespace"
    )?;
    
    collector.start(5).await?; // 5-second windows
    
    // Record events
    for i in 0..100 {
        let event = create_test_event(i);
        collector.record_event(event).await?;
    }
    
    // Seal and export
    collector.seal_window().await?;
    let path = collector.export_proofpack("./output").await?;
    
    println!("Exported proofpack to: {}", path);
    Ok(())
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Your Application                      │
├─────────────────────────────────────────────────────────────┤
│  ritma_lab (demo)  │  ritma_cli (CLI)  │  Your Custom Code  │
├─────────────────────────────────────────────────────────────┤
│                     bar_orchestrator                         │
│            (13-stage seal pipeline + RTSL)                   │
├────────────────┬────────────────┬───────────────────────────┤
│   forensic_ml  │   snapshotter  │   attack_graph            │
│   (4-layer ML) │   (capture)    │   (threat detection)      │
├────────────────┴────────────────┴───────────────────────────┤
│                        index_db                              │
│              (SQLite + custody log v2)                       │
├─────────────────────────────────────────────────────────────┤
│                     ritma_contract                           │
│           (StorageContract, CAS, RTSL writer)                │
├─────────────────────────────────────────────────────────────┤
│                     common_models                            │
│        (TraceEvent, WindowPageV2, ProofPack, etc.)           │
└─────────────────────────────────────────────────────────────┘
```

## Key Crates

| Crate | Purpose |
|-------|---------|
| `common_models` | Core types: TraceEvent, WindowRange, ProofPack |
| `index_db` | Event storage, custody log, sealed windows |
| `ritma_contract` | StorageContract, CAS, RTSL output |
| `bar_orchestrator` | 13-stage BAR pipeline |
| `forensic_ml` | 4-layer forensic ML with notarization |
| `security_interfaces` | PipelineOrchestrator trait |
| `snapshotter` | Process tree, socket, container capture |
| `attack_graph` | Threat detection and graph analysis |

## Output Format

### Proofpack Structure
```
proofpack/
├── manifest.json           # Bundle metadata
├── windows/
│   └── YYYY/MM/DD/HH/
│       ├── window_page.cbor     # Canonical sealed window
│       ├── window_page.sig.cose # COSE_Sign1 signature
│       └── leaves.cbor.zst      # Event hashes
├── chain.json              # Hash chain continuity
└── custody_log.jsonl       # Audit trail
```

### Window Page (CBOR)
```json
{
  "version": "ritma-page@0.2",
  "namespace_id": "my-app",
  "window": { "start_ts": 1768893279, "end_ts": 1768893579 },
  "merkle_root": "abc123...",
  "event_count": 1500,
  "ml_notary_hash": "def456...",
  "forensic_verdict": "normal",
  "forensic_score": 0.12,
  "prev_hash": "789abc..."
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RITMA_NODE_ID` | auto | Node identifier |
| `RITMA_BASE_DIR` | `/var/lib/ritma` | Base data directory |
| `RITMA_OUT_DIR` | `$BASE/out` | Proofpack output |
| `RITMA_OUT_ENABLE` | `0` | Enable RTSL output |
| `RITMA_CAS_ENABLE` | `0` | Enable CAS storage |
| `RITMA_PRIVACY_MODE` | `full` | Privacy level |
| `RITMA_WINDOW_SECONDS` | `300` | Window duration |
| `RITMA_KEY_ID` | none | Signing key ID |

## License

Apache 2.0 - See [LICENSE](https://github.com/GlobalSushrut/ritma-utl/blob/main/LICENSE)
