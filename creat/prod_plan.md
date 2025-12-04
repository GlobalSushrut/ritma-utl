# Ritma Production Architecture & Rollout Plan

This document describes how to evolve the current Ritma prototype into a production-grade security + compliance fabric.

## Phase 1 – Harden the Core Truth Layer

**Objectives**

- Make `utld` durable, restart-safe, and ready for HA deployments.
- Preserve the existing JSON-over-unix API and policy model.

**Key work items**

1. **Durable counters and node state**
   - Persist `policy_engine` counters (e.g. `patient_search_requests`) into a store (SQLite/Postgres/RocksDB).
   - On startup, load counters so policy behavior is stable across restarts.
   - Expose an admin API to reset counters or start new windows per root/tenant.

2. **Process model and HA**
   - Clarify that `utld` is:
     - either stateless + backed by a central state store, or
     - a single-writer primary with optional readers.
   - Document deployment topologies (single instance, active/passive, active/active with sharding by `root_id`).

3. **Security hardening**
   - Lock down the `UTLD_SOCKET` interface:
     - `SO_PEERCRED`/mTLS or a dedicated sidecar pattern.
   - Enforce structured error handling and input validation on all NodeRequest variants.

## Phase 2 – Forensic Vault Implementation

**Objectives**

- Move DigFiles from local `./dig` to a durable object-store-based forensic vault.
- Provide a DB-backed index for efficient queries over forensic history.

**Key work items**

1. **Object storage backend**
   - Implement a `forensics_store` module that persists DigFiles to an S3-compatible API using the layout:

     ```text
     forensics/<tenant_id>/<YYYY>/<MM>/<DD>/root-<root_id>_file-<file_id>_<timestamp>.dig.json
     ```

   - Make the backend pluggable (file-system, S3, GCS, MinIO).
   - Add retries and backoff for persistence errors; surface failures via metrics and logs.

2. **Dig index service**
   - Introduce a small `dig_index` crate or service that records metadata per sealed DigFile:
     - `file_id`, `tenant_id`, `root_id`, `time_start`, `time_end`, `record_count`, `merkle_root`.
     - `policy_name`, `policy_version`, `policy_decision`.
     - `storage_path` and optional `chain_anchor_id`.
   - Add a lightweight HTTP API to query:
     - Digs by tenant and time range.
     - Digs where `policy_decision = 'deny'`.

3. **Anchoring (optional v1)**
   - Batch merkle roots for new DigFiles and store batch roots in an internal table.
   - Provide hooks for external anchoring (to BPI / blockchain) but defer implementation to a later phase.

## Phase 3 – Security OS Integration

**Objectives**

- Use `security_os` traits to enforce isolation and firewall behavior at the OS/network level.

**Key work items**

1. **Decision event stream**
   - Emit a structured decision event whenever a policy fires, including:
     - `tenant_id`, `root_id`, `entity_id`, `event_kind`.
     - `policy_name`, `policy_rules`, `policy_decision`, `policy_actions`.
     - DIDs/zones (`src_did`, `dst_did`, `src_zone`, `dst_zone`, `actor_did`).

2. **Host agent implementing `FirewallController` and `CgroupController`**
   - Out-of-repo daemon that:
     - Subscribes to decision events.
     - Applies `FlowDecision` and `IsolationProfile` via iptables/nftables and cgroups v2.
   - Enforce zone and service policies such as:
     - No direct `public -> restricted` flows.
     - Throttle misbehaving services.

3. **Zero-trust enforcement
**
   - Require that all prod events include DIDs and zones.
   - Reject events that cannot be mapped to a `tenant_id` + `src_did` + `dst_did` + `src_zone` + `dst_zone`.

## Phase 4 – Tenant Lawbooks & Governance

**Objectives**

- Move from static JSON policies to tenant-managed lawbooks with platform validation.

**Key work items**

1. **Lawbook registry service**
   - Store versioned tenant lawbooks (CUE and JSON).
   - Workflow:
     - Tenant submits CUE lawbook.
     - Registry validates with `cue vet` + Rust validator.
     - Registry compiles to TruthScript JSON policy usable by `utld`.

2. **Platform constitution enforcement**
   - Encode non-negotiable constraints in both CUE schema and Rust validators:
     - Certain event kinds must always log (`must_log`) and/or seal (`seal_digfile`).
     - Tenants cannot define policies that weaken baseline protections.

3. **Per-tenant auth & RBAC**
   - Replace single `UTLD_API_TOKEN` with per-tenant API credentials.
   - Add roles/scopes for lawbook management vs. data-plane operations.

## Phase 5 – Observability & Compliance Readiness

**Objectives**

- Provide the telemetry, tests, and documentation required for real deployments (SOC2/ISO/HIPAA alignment).

**Key work items**

1. **Observability**
   - Structured JSON logging with correlation IDs, tenant, root, DID, and policy fields.
   - Prometheus/OpenTelemetry metrics for:
     - `transitions_total`, `transition_errors_total`, `dig_seals_total`, `entropy_bins_total`.
     - Per-policy allow/deny counts.
     - Sensor hits (e.g. `sql_injection`, `auth_bruteforce`).

2. **Testing and chaos**
   - Integration tests that:
     - Drive multi-tenant traffic through HTTP, AI, access, payments, and security flows.
     - Validate dig contents and policy decisions.
   - Chaos tests:
     - Object store failures.
     - DB outages.
     - `utld` restarts during heavy load.

3. **Compliance mapping**
   - Document how DigFiles, policies, and anchors satisfy common controls:
     - Immutable logs.
     - Access audit trails.
     - Security incident detection & response.
   - Provide configuration examples for data residency and tenant-level retention.

---

## Near-term Implementation Plan (concrete next steps)

1. Add a minimal `dig_index` module that logs metadata on DigFile seal and writes rows to a local SQLite/JSON index.
2. Introduce a simple HTTP endpoint (or CLI option) to list DigFiles by tenant and time range using this index.
3. Prototype an S3-backed `forensics_store` implementation while preserving `./dig` for dev.
4. Expand the decision event structure and define a stable schema to be consumed by an external host agent.

These steps move Ritma from a powerful prototype into a service with clear production pathways, without disrupting existing demos or developer workflows.
