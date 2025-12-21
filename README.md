# Ritma / Universal Truth Layer (UTL)

Ritma is an experimental **Universal Truth Layer (UTL)** for security: a
policy-driven fabric that sits between applications and the operating system.
It evaluates policies on every transition, enforces allow/deny decisions, and
produces verifiable forensic evidence of what actually happened.

This repository contains the first production slice of the **Pravyom** project:

- A live policy firewall (`utld`).
- A forensic vault with DigFiles and an index.
- A forensics HTTP API (`utl_forensics`).
- A decision event stream and host agent stub (`security_host`).

---

## What Ritma Has Become (2025-12)

Ritma has evolved into an end‑to‑end, evidence‑first security fabric. In addition to the UTL core, the workspace now includes:

- 8 grounded detection phases as composable crates (fileless, eBPF hardening, APT tracking, container/K8s, memory forensics, network analysis, hardware, ML).
- A BAR pipeline (policy verdicting primitives) and orchestration components.
- Evidence packaging, indexing (SQLite/JSONL), and signing via a node keystore.
- A CLI with a truthful‑by‑default, fully grounded enhanced demo and an attestation command that emits verifiable artifacts.

This section summarizes how to experience the system quickly and verify every claim from artifacts produced during a run.

### Quick Start (Grounded Demo + Attestation)

```bash
# 1) Run the grounded 8‑phase demo (invokes real crate APIs)
cargo run --bin ritma_cli -- demo-enhanced

# 2) Create a repository/file‑tree attestation and QR (optional QR via flags)
cargo run --bin ritma_cli -- attest \
  --path . \
  --namespace ns://demo/dev/hello/world
```

The demo prints a final "Evidence Pack" section containing:

- namespace_id, window_id
- attack_graph_hash
- evidence_pack_path (JSON payload written to disk)
- receipt_hash (sha256 of the payload)
- proof_status (generated/skipped)

The demo avoids named actor claims by default. It reports evidence‑based classification (cluster ID, template match, TTP bundle, confidence). Predictive lines use conservative wording (e.g., "ransomware‑like behavior risk" + horizon) and never overstate certainty.

### Module Map (high‑level)

- Detectors (8 phases): `fileless_detector`, `ebpf_hardening`, `apt_tracker`, `container_security`, `memory_forensics`, `network_analysis`, `hardware_monitor`, `ml_detector`
- BAR core: `bar_core`, `bar_orchestrator`, `bar_pipeline`, `bar_daemon`
- Evidence + Index: `evidence_package`, `forensics_store`, `dig_index`, `index_db`
- Keys + Identity: `node_keystore`, `handshake`
- Compliance (alpha): `compliance_engine`, `compliance_index`, `compliance_packs`
- CLI: `ritma_cli` (demo‑enhanced, attest)

For detailed component docs, see each crate’s README where available.

---

### Truthful‑by‑Default Policy

- Evidence‑first output. The demo and CLI avoid threat‑actor naming by default.
- Classification is reported as:
  - Cluster ID (e.g., campaign_a1b2c3d4)
  - Template match (e.g., supply‑chain‑beacon‑v1)
  - TTP bundle (MITRE ATT&CK techniques)
  - Confidence noted with rationale (e.g., feature match + beacon regularity)
- Predictive language is conservative (e.g., "ransomware‑like behavior risk") and includes horizon when applicable.

### Verify the Evidence

After running `demo-enhanced`, check the final Evidence Pack lines:

1. Read the JSON: `cat <evidence_pack_path>/demo_evidence.json`
2. Verify receipt hash:
   - `sha256sum <evidence_pack_path>/demo_evidence.json | cut -d' ' -f1`
   - Compare to the printed `receipt_hash`
3. Recompute `attack_graph_hash` per the printed construction (namespace_id|window_id) if needed.

To generate a repository attestation artifact:

```bash
cargo run --bin ritma_cli -- attest --path . --namespace ns://demo/dev/hello/world
```

Outputs include the attestation directory and a `sha256` receipt in the console (or JSON with `--json`).

---

## High-Level Architecture

At a high level, UTL does three things:

1. **Enforce** – Every transition (e.g. `RecordTransition`) is evaluated
   against a TruthScript policy by `utld`. The policy can:
   - Allow the transition.
   - Deny it with a reason.
   - Allow with additional actions (e.g. seal a DigFile, require a proof).

2. **Record** – For selected transitions, `utld` seals **DigFiles**:
   - Merkle-rooted, append-only JSON logs of DigRecords.
   - Written to a local `./dig` directory.
   - Mirrored into an S3-style forensics tree under `./forensics`.
   - Indexed with minimal metadata in `dig_index.jsonl` and optionally
     `dig_index.sqlite`.

3. **Explain** – Every policy evaluation that produces actions emits a
   **DecisionEvent**:
   - Structured JSONL log with tenant, root, entity, event kind.
   - Includes policy decision, rules, and actions.
   - Optional identity context (DIDs, zones).
   - Consumed by `security_host` to simulate a host-level agent.

---

## Repository Layout

Key crates and binaries:

- `crates/utld` – main UTL daemon (policy engine + dig sealing + decision events).
- `crates/utl_forensics` – HTTP forensics API over the dig index and forensics store.
- `crates/utl_cli` – CLI for interacting with UTL (roots, transitions, digs).
- `crates/dig_index` – Dig index types and JSONL/SQLite index writer.
- `crates/forensics_store` – S3-style filesystem layout for DigFiles.
- `crates/security_events` – `DecisionEvent` schema and JSONL appender.
- `crates/security_host` – host agent stub that reads decision events and
  calls `security_os` traits.
- `crates/security_os` – abstract interfaces for firewall and isolation
  controllers.

The workspace is defined in the top-level `Cargo.toml`.

---

## Building the Workspace

Requirements:

- Rust (stable toolchain).
- SQLite (via the bundled `rusqlite` feature included in `dig_index`).

To build everything:

```bash
cd ~/Documents/connector/ritma
cargo build
```

To run tests (where present):

```bash
cargo test
```

---

## Core Runtime: `utld`

`utld` is the central daemon. It listens on a Unix socket and processes
`NodeRequest` messages:

- `RegisterRoot` – register a new root of truth.
- `RecordTransition` – apply a policy to a transition and maybe seal/deny.
- `BuildDigFile` – request construction of a DigFile over a time window.

### Running `utld`

```bash
cd ~/Documents/connector/ritma

export UTLD_POLICY=creat/policies/security_policy.json
export UTLD_DIG_INDEX=./dig_index.jsonl
export UTLD_DIG_DIR=./dig
export UTLD_FORENSICS_DIR=./forensics
export UTLD_DIG_INDEX_DB=./dig_index.sqlite    # optional, enables SQLite index
export UTLD_DECISION_EVENTS=./decision_events.jsonl

cargo run -p utld
```

`utld` will listen on the Unix socket given by `UTLD_SOCKET` (default
`/tmp/utld.sock`).

---

## Forensics HTTP API: `utl_forensics`

`utl_forensics` serves indexed DigFiles over HTTP with bearer token auth.

### Running

```bash
cd ~/Documents/connector/ritma

export UTL_FORENSICS_ADDR=127.0.0.1:9101
export UTL_FORENSICS_TOKEN="secret"

cargo run -p utl_forensics
```

### Key endpoints

- `GET /health` – health check.
- `GET /digs` – list digs with filters.
  - Query parameters:
    - `tenant`
    - `root_id`
    - `policy_decision` (e.g. `allow_with_actions`, `deny`)
    - `since`, `until` (UNIX timestamps in seconds)
    - `limit` (max number of results)
    - `show_path` (include on-disk paths)
- `GET /digs/:file_id` – details for a specific dig.
- `GET /evidence/:file_id` – compact evidence bundle for audits.

Example query:

```bash
curl -H "Authorization: Bearer secret" \
  "http://127.0.0.1:9101/digs?tenant=acme&root_id=300&policy_decision=allow_with_actions&show_path=true" \
  | jq
```

---

## CLI: `utl_cli`

`utl_cli` is the main way to drive the daemon and inspect results from a shell.

### Example commands

List registered roots:

```bash
cargo run -p utl_cli -- roots-list
```

Register a root:

```bash
cargo run -p utl_cli -- \
  root-register --root-id 300 --root-hash <hex> \
  --param tenant_id=acme
```

Record a transition:

```bash
cargo run -p utl_cli -- \
  tx-record --entity-id <id> --root-id 300 \
  --signature <hex> --data "payload" --addr-heap-hash <hex> \
  --hook-hash <hex> --logic-ref "ref" --wall "boundary" \
  --param tenant_id=acme
```

List digs from the index:

```bash
cargo run -p utl_cli -- digs-list --show-path
```

Inspect a dig by `file_id`:

```bash
cargo run -p utl_cli -- \
  dig-inspect-id --file-id <file_id> --limit 5
```

The CLI uses the same dig index and DigFile paths as the forensics service.

---

## Forensic Storage and Indexing

### DigFiles

When policy actions such as `SealCurrentDig` (or `Deny`) fire, `utld` seals
DigFiles per root. Each DigFile:

- Contains a sequence of DigRecords with timestamps and parameters.
- Has a Merkle root committing to the records.
- Is written under `UTLD_DIG_DIR` (default `./dig`).

### Forensics store (S3-style layout)

In addition to `./dig`, DigFiles are mirrored into an S3-style layout on disk
by the `forensics_store` crate:

```text
forensics/<tenant>/<YYYY>/<MM>/<DD>/root-<root_id>_file-<file_id>_<ts>.dig.json
```

The base directory is configured by `UTLD_FORENSICS_DIR` (default `./forensics`).

### Dig index (JSONL + SQLite)

Every sealed DigFile appends a `DigIndexEntry` to:

- `UTLD_DIG_INDEX` (default `./dig_index.jsonl`).
- Optionally `UTLD_DIG_INDEX_DB` (e.g. `./dig_index.sqlite`) via `dig_index`
  and `rusqlite`.

Index entries store:

- `file_id`, `root_id`, `tenant_id`.
- `time_start`, `time_end`, `record_count`, `merkle_root`.
- `policy_name`, `policy_version`, `policy_decision`.
- `storage_path` (forensics path, when available).

This index powers both the CLI and the forensics HTTP API.

---

## Decision Events and Host Agent

For every policy evaluation with actions, `utld` emits a `DecisionEvent` to a
JSONL log (`UTLD_DECISION_EVENTS`, default `./decision_events.jsonl`). A
`DecisionEvent` includes:

- `ts` (timestamp).
- `tenant_id`, `root_id`, `entity_id`, `event_kind`.
- `policy_name`, `policy_version`, `policy_decision`.
- `policy_rules`, `policy_actions`.
- Optional `src_did`, `dst_did`, `actor_did`, `src_zone`, `dst_zone`.

### security_host

The `security_host` binary simulates a host agent that consumes these events:

```bash
export SECURITY_EVENTS_PATH=./decision_events.jsonl
cargo run -p security_host
```

It:

- Reads each `DecisionEvent` from the JSONL stream.
- Logs a human-readable summary (decision, DIDs, zones).
- Calls `FirewallController` and `CgroupController` trait implementations that
  currently just log intended actions.

This is the starting point for a real Pravyom host agent.

---

## Environment Variables (Quick Reference)

- `UTLD_POLICY` – path to the TruthScript policy used by `utld`.
- `UTLD_SOCKET` – Unix socket for `utld` (default `/tmp/utld.sock`).
- `UTLD_DIG_INDEX` – path to dig index JSONL file (default `./dig_index.jsonl`).
- `UTLD_DIG_DIR` – path to legacy DigFile directory (default `./dig`).
- `UTLD_FORENSICS_DIR` – base directory for forensics store (default `./forensics`).
- `UTLD_DIG_INDEX_DB` – optional SQLite DB path for dig index mirror.
- `UTLD_DECISION_EVENTS` – path to decision events JSONL log.
- `UTL_FORENSICS_ADDR` – address for forensics HTTP API (e.g. `127.0.0.1:9101`).
- `UTL_FORENSICS_TOKEN` – bearer token for forensics API auth.
- `SECURITY_EVENTS_PATH` – path to decision events log for `security_host`.

---

## Status and Next Steps

This codebase already supports:

- Live policy enforcement on transitions.
- Sealed DigFiles and an indexed forensic vault.
- Time- and policy-based dig queries via HTTP.
- Structured decision events driving a host-agent stub.

Planned evolution under the Pravyom programme includes deeper host-level
isolation, richer lawbook governance, and stronger cryptographic proofs, all
building on the primitives implemented here.
