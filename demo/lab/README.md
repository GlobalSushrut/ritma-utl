# Ritma Lab

**Military-grade forensic evidence demo** - demonstrating the full Ritma forensic pipeline with explainable ML, RTSL proofpacks, and proof-of-custody standard.

## What Makes This Real Ritma Standard

| Component | Description |
|-----------|-------------|
| **ForensicML** | 4-layer ML (deterministic + statistical + embeddings + verdict synthesis) |
| **ML Notary** | Cryptographic attestation with model/feature/weight hashes |
| **BAR Pipeline** | Full 13-stage seal pipeline with auto-prune |
| **RTSL Proofpack** | v2 format with page_hash, chain continuity, CT-style leaves |
| **Custody Chain** | Tamper-evident hash chain linking all windows |

## Quick Start

```bash
# Build the lab
cd demo/lab
cargo build --release

# Initialize a new lab
./target/release/ritma-lab init --path ./my-lab

# Run a scenario
./target/release/ritma-lab run \
  --topology topologies/three-tier.yaml \
  --scenario scenarios/baseline.yaml

# Export proofpack
./target/release/ritma-lab export --output ./output

# Verify proofpack
./target/release/ritma-lab verify ./output
```

## Directory Structure

```
demo/lab/
├── ritma_lab/           # Main orchestrator CLI
├── ritma_lab_proto/     # Shared protocol definitions
├── ritma_lab_node/      # Node runtime (for containers)
├── topologies/          # Topology definitions
│   └── three-tier.yaml
├── scenarios/           # Scenario definitions
│   ├── baseline.yaml
│   ├── ransomware.yaml
│   ├── ai-audit.yaml
│   ├── healthcare.yaml
│   ├── financial.yaml
│   └── network.yaml
└── docker/              # Container images
```

## 5 Niche Scenarios

| Scenario | File | Duration | Use Case |
|----------|------|----------|----------|
| **Baseline** | `baseline.yaml` | 60s | Normal traffic pattern |
| **Ransomware** | `ransomware.yaml` | 120s | Attack forensics, PIPEDA/Law 25 |
| **AI Audit** | `ai-audit.yaml` | 120s | EU AI Act, model governance |
| **Healthcare** | `healthcare.yaml` | 120s | HIPAA, PHI access audit |
| **Financial** | `financial.yaml` | 120s | SOX, PCI-DSS, MiFID II |
| **Network** | `network.yaml` | 120s | Zero Trust, lateral movement |

## CLI Commands

```bash
ritma-lab init [--path PATH]           # Initialize lab directory
ritma-lab up [--topology T] [--scenario S]  # Start lab
ritma-lab down [--force]               # Stop lab
ritma-lab status                       # Show status
ritma-lab run --scenario S [--topology T]   # Run scenario
ritma-lab export --output PATH         # Export proofpack
ritma-lab verify PATH                  # Verify proofpack
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LAB ORCHESTRATOR                          │
│  Topology Manager │ Scenario Engine │ Chaos │ Evidence      │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   NODE-WEB   │───▶│   NODE-API   │───▶│   NODE-DB    │
│  + Ritma     │    │  + Ritma     │    │  + Ritma     │
└──────────────┘    └──────────────┘    └──────────────┘
        │                     │                     │
        └─────────────────────┴─────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  EVIDENCE CHAIN   │
                    │  → Proofpack      │
                    └───────────────────┘
```

## Evidence Output (v2 Forensic Standard)

After running a scenario, the proofpack contains:

```
output/
├── manifest.json      # v2 bundle metadata with ForensicML stats
├── windows.cbor       # Sealed windows (canonical CBOR)
├── windows.json       # Sealed windows (readable JSON)
└── chain.json         # Hash chain with ML notary hashes
```

### Window Structure (v2)

Each sealed window includes:

```json
{
  "window_id": "w_1705789200_1705789260",
  "namespace_id": "ns://lab/demo",
  "event_count": 142,
  "merkle_root": "a3f2...",
  "page_hash": "b7c1...",           // Includes ML notary hash
  "ml_notary_hash": "d4e5...",      // ForensicML attestation
  "forensic_verdict": "benign",     // hostile|anomalous|benign
  "forensic_score": 0.23,
  "chain_hash": "f8a9...",          // Links to previous
  "prev_chain_hash": "c6d7..."
}
```

### ForensicML Output

Every window includes explainable ML analysis:

- **Layer A**: Deterministic features (graph, temporal, entropy, privilege, IO)
- **Layer B**: Statistical anomaly (Isolation Forest, LOF, HMM)
- **Layer C**: Behavior embeddings with similarity risk
- **Layer D**: Verdict synthesis with policy violations

## Verification

```bash
$ ritma-lab verify ./output

Verifying proofpack: ./output
  Manifest version: 1.0
  Windows: 24
  Chain length: 24

✓ VERIFICATION PASSED
  Chain is continuous and valid
  All merkle roots verified
```

## Development

```bash
# Run tests
cargo test --workspace

# Build release
cargo build --release --workspace

# Run with debug logging
RUST_LOG=ritma_lab=debug ./target/release/ritma-lab run ...
```
