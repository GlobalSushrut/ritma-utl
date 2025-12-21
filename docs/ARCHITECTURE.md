# Ritma Architecture (Deep Dive)

Truthful-by-default. This document describes what exists now, how components interact, and where live integrations must be explicitly wired by an operator.

## 1. Overview

Ritma is an evidence-first security fabric. It combines:

- Detector layer (8 grounded crates) for modeling host, container, network, hardware, and ML signals
- BAR layer (policy verdict primitives) for ingesting observed events and producing decisions
- Evidence & Index layer for packaging, signing, and retrieval
- CLI for demonstrations, attestation, and export flows

It is designed to be modular. By default, the demo uses simulated inputs into the detector APIs (no hidden live hooks). Operators can wire real data sources later.

## 2. Components

- Detectors (8 phases)
  - fileless_detector (fileless execution, injection, tmpfs exec)
  - ebpf_hardening (evasion signals: direct syscalls, probe tampering, n-gram anomalies)
  - apt_tracker (cross-window correlation, beaconing, dormant backdoor, campaign clustering)
  - container_security (escape conditions, K8s API abuse, lateral movement, registry poisoning)
  - memory_forensics (rootkits, suspicious modules, memory injection, DKOM)
  - network_analysis (DPI, protocol anomalies, encrypted fingerprinting)
  - hardware_monitor (CPU perf counters, Rowhammer, PCIe scanning)
  - ml_detector (behavioral anomalies, hunts, predictive alerts)

- BAR (policy pipeline primitives)
  - bar_core: `ObservedEvent`, `PolicyVerdict`, `BarAgent` traits; `NoopBarAgent`, `SimpleRuleBarAgent`
  - bar_orchestrator: composition helpers (early scaffolding)

- Evidence, Index & Packaging
  - evidence_package (manifests, signing; supports keystore and env key)
  - index_db (SQLite interface for ML scores/evidence retrieval in export)
  - dig_index/forensics_store (referenced in top-level READMEs; used by other binaries)

- Keys & identity
  - node_keystore (HMAC/Ed25519-based signing source for packaging)

- CLI
  - ritma_cli (grounded demo, attestation, observe-only BAR, export flows)

## 3. Data Flows

### 3.1 Grounded 8‑phase demo (ritma_cli demo-enhanced)

- The CLI instantiates each detector/manager and feeds realistic, deterministic inputs
- Each crate returns alerts/evidence structs; these are printed and summarized
- A minimal Evidence Pack JSON is written (namespace_id, window_id, generated_at, notes)
- A `receipt_hash` is computed as `sha256(evidence_json)`
- An `attack_graph_hash` is derived from `sha256(namespace_id|window_id)` for reproducibility

Important: the demo does not attach to live eBPF, kernel, network, or PCIe. It showcases the API surfaces and the kinds of evidence/alerts these crates return when fed representative inputs.

### 3.2 BAR observe-only loop (ritma_cli bar-run-observe-only)

- Reads JSON events from stdin, maps to `ObservedEvent`
- Evaluates with `NoopBarAgent` (fail-open; returns `ObserveOnly`)
- Prints decision and optional reason

This provides a safe stub for integrating real event sources later.

### 3.3 Evidence packaging (export-incident)

- Uses `evidence_package` to build a manifest over a scoped time range (when index/db available)
- Signs with `node_keystore` if configured, otherwise attempts env-based signing; if neither present, computes a hash
- Outputs a manifest (JSON) and logs signer/package-hash details

## 4. Boundaries & Integration Points

- OS instrumentation (eBPF, syscall hooks, perf): not enabled by default
  - Operators must deploy and wire OS-level providers and feed the detectors
- Kubernetes control-plane/user-plane: this crate analyzes provided K8s API call records
- Packet capture: DPI expects payloads from a capture source (pcap, SPAN, agent) provided by the caller
- PCI/CPU counters: requires a reader to supply counters; the library analyzes values
- Threat intelligence: named actor mapping is off-by-default; feed intel and enable a caller-side feature flag to opt in

## 5. Truthful‑by‑Default Policy

- Evidence-first outputs; do not assert named attribution by default
- Classification: cluster, template, TTPs, confidence with rationale
- Predictive: conservative wording ("<threat>-like behavior risk") and horizon when available

## 6. Operational Considerations

- Deterministic demo: same inputs, stable output shape and evidence hashes (modulo timestamps/UUIDs)
- Attestation: repository/file-tree attestation produces canonical JSON and a receipt hash
- Signing: prefer node_keystore; fallback env key; otherwise unsigned hash

## 7. Roadmap (grounded)

- Live wiring: add agent(s) for eBPF, perf, packet capture, K8s audit logs
- Evidence: richer pack schema + full-chain verification tooling
- BAR: policy packs, obligations, and enforcement pathways
- Compliance: expand rulepacks and reporting
