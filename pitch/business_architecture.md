# Ritma Business Architecture – Open Core + 26 Commercial Products

> How Ritma’s **open-core truth layer** turns into a **portfolio of 26 sellable services**, without ever closing the core.

---

## 1. Architectural Principles

1. **Open Core, Paid Infrastructure**  
   - All **verification-critical components** (utld, TruthScript, CUE schemas, zk circuits, dig/ledger formats) stay free and open source.  
   - Revenue comes from running **reliable, global infrastructure** and providing **managed services**, not from locking up protocols or formats.

2. **Clear OSS vs SaaS Boundary**  
   - Anything required to **reconstruct and verify history locally** is OSS.  
   - SaaS adds: multi-tenant control plane, global witness/anchoring, evidence vaults, analytics, and UX.

3. **Productization, Not Monolith**  
   - Ritma Cloud is architected as a **family of products** (26 distinct but composable services), not one big SKU.  
   - Each product has: clear inputs (dig/index/policy/decision streams), outputs (APIs, dashboards, reports), and pricing axis.

4. **Ultimate Truth Layer**  
   - All products reinforce the same core promise: **"we record what happened and why, and anyone can verify it"**.  
   - Even when customers churn, they keep all evidence and can still verify it with OSS tools.

---

## 2. Layered Business Architecture

### 2.1 OSS Data Plane (Self-Hosted or Vendor-Hosted)

Core components (always free):

- `utld` – policy enforcement daemon and dig writer.  
- `utl_cli` – CLI for policy loading, dig inspection, snapshots, etc.  
- `truthscript`, `policy_engine`, `tenant_policy` – policy semantics and lawbooks.  
- `dig_mem`, `dig_index`, `security_events` – Merkle DigFiles, hash-chained dig index, decision events.  
- `zk_snark`, `distillium`, `entropy_tree`, `tracer`, `forensics_store`, `trust_container` – cryptographic and telemetry primitives.

This layer can run **entirely in a customer’s environment** without touching Ritma Cloud.

### 2.2 Ritma Cloud Control Plane

SaaS control plane functions:

- Multi-tenant account model (customers, tenants, projects).  
- Configuration of utld clusters, ingestion endpoints, keys, and policies.  
- Management APIs, web console, RBAC, SSO.

### 2.3 Evidence & Witness Plane

SaaS services that operate on **hashes, snapshots, and DigFiles**, not raw secrets:

- Global witness network for signing and mirroring snapshot heads.  
- External anchoring into public timestamping / blockchains.  
- Managed evidence vaults and forensic indexing.

### 2.4 Product Layer (26 Commercial Services)

On top of the evidence plane, Ritma exposes 26 sellable products grouped into five domains:

1. **Platform & Witnessing (P1–P6)**  
2. **Policy & Governance (G1–G7)**  
3. **AI & Behavioral Security (A1–A6)**  
4. **Evidence & Forensics (E1–E4)**  
5. **Access, Portals & Integrations (X1–X3)**

Each product is powered by one or more OSS crates and exposes higher-level value via APIs/UI.

---

## 3. Platform & Witnessing Products (P1–P6)

### P1. Managed utld Clusters

- **Role:** Operate `utld` as a managed, multi-region service.  
- **Inputs:** RecordTransition traffic, policy bundles, tenant configs.  
- **Outputs:** DigFiles, dig_index, decision_events, snapshots.  
- **OSS Base:** `utld`, `utl_cli`, `dig_mem`, `dig_index`, `security_events`.  
- **Why Sellable:** Customers offload ops (upgrades, HA, backups) but can still export DigFiles and verify locally.

### P2. Global Witness Network

- **Role:** Provide independent witnesses that subscribe to snapshot exports and heads.  
- **Inputs:** `truth_snapshot_export` payloads (index head, policy ledger head).  
- **Outputs:** Witness signatures, attestations, cross-jurisdiction mirrors.  
- **OSS Base:** snapshot CLI + signing/verification primitives.  
- **Why Sellable:** Running a diverse, audited witness network is infra-heavy and offers strong non-equivocation guarantees.

### P3. External Anchoring Service

- **Role:** Periodically anchor snapshots into public chains/timestamp services.  
- **Inputs:** Snapshot hashes from P2.  
- **Outputs:** On-chain tx IDs, proofs of inclusion.  
- **OSS Base:** Hashing & snapshot formats.  
- **Why Sellable:** Manages fees, chain diversity, and rotation; customers can still independently check anchors.

### P4. Truth Snapshot Scheduler

- **Role:** Managed scheduling of periodic snapshots across roots/tenants.  
- **Inputs:** Tenant configs (frequency, scope), utld heads.  
- **Outputs:** Regular snapshot events + export payloads.  
- **OSS Base:** `TruthSnapshot` commands and snapshot structs.  
- **Why Sellable:** Turn-key truth baselining across many environments.

### P5. Compliance & SLA Reporting Engine

- **Role:** Convert evidence (snapshots, DigFiles, decisions) into reports and dashboards.  
- **Inputs:** All evidence streams.  
- **Outputs:** SLA adherence, control coverage, audit-ready PDFs/JSON reports.  
- **OSS Base:** Data formats and queries can be reproduced locally.  
- **Why Sellable:** Pre-built reporting pipelines and compliance mapping.

### P6. Key & Secret Orchestration

- **Role:** Manage HMAC / zk / Distillium keys for utld nodes.  
- **Inputs:** Key material or KMS/HSM references.  
- **Outputs:** Short-lived signing keys pushed to nodes, rotation logs.  
- **OSS Base:** Key usage in utld; core crypto remains open.  
- **Why Sellable:** Operating secure, audited key pipelines across fleets is difficult; this is classic SaaS value.

---

## 4. Policy & Governance Products (G1–G7)

### G1. Policy Studio (TruthScript + CUE)

- Web-based editor and validator for CUE and TruthScript policies.  
- Live validation against `truthscript.cue`, `tenant_lawbook.cue`, `events.cue`.  
- Version control, diffing, and approval workflows.

### G2. Policy Burn & Governance Ledger Service

- Managed view over policy burns and versions.  
- Uses on-disk policy ledgers plus DigRecords on the dedicated policy root.  
- Visual timelines of policy changes, who approved them, and which DigFiles they affect.

### G3. Lawbook & Control Library

- Catalog of lawbooks and control sets per sector.  
- Signed artifacts with change history and compatibility metadata.  
- Customers subscribe to control packs and customize them.

### G4. Policy Simulation-as-a-Service

- Run new policies against historical DigFiles/DecisionEvents.  
- Show would-have-fired rules, denies, and SNARK requirements.  
- Helps teams safely iterate on policies.

### G5. Policy CI / CD Integration

- GitHub/GitLab/CI plugins that:
  - Validate policies and lawbooks at commit time.  
  - Generate burn proposals, requiring approvals before merging.  
- Bridges developer workflows with governance.

### G6. Third-Party Policy Marketplace

- Marketplace where auditors, regulators, and vendors publish policies/lawbooks.  
- Customers can buy/subscribe to curated rule sets; Ritma takes a revenue share.

### G7. Regulator & Auditor Portal (Governance View)

- Special access tier for regulators/auditors:  
  - Read-only dashboards over snapshots, burns, and denies.  
  - Tools to verify claims using the same hash chains and proofs.  
- Builds trust that Ritma’s platform is neutral and verifiable.

---

## 5. AI & Behavioral Security Products (A1–A6)

### A1. AI Guardrail Pack

- Library of AI-specific policies (LLM usage, PII leakage, jailbreak detection).  
- Uses TruthScript conditions and the CUE event schema for AI calls.  
- Bundled dashboards for AI traffic and denies.

### A2. Entropy Analytics & Drift Detection

- Managed analytics over `entropy_tree` metrics.  
- Detects unusual entropy patterns (e.g., replay, exfil, synthetic traffic).  
- Feeds into risk scores and alerts.

### A3. Unknown Logic Registry

- Central registry for `UnknownLogicCapsule`s:  
  - Where foreign code runs, bridge info, input/output snapshots.  
- Queries such as “all capsules touching asset X in last 24h.”

### A4. Distillium Micro-Proof Service

- Hosted registry of `DistilliumMicroProof`s.  
- APIs to generate, store, and verify micro-proofs for arbitrary state hashes.  
- Bridges internal state changes to the global truth layer.

### A5. Trust Agreement Service

- Managed `TrustAgreementContainer`s for cross-party agreements.  
- Visual, zk-backed mapping from contracts to actual micro-proof chains.

### A6. Anomaly Detection-as-a-Service

- Aggregated (privacy-preserving) analytics over entropy, capsules, and decision patterns.  
- ML models to detect previously unseen attack or abuse behaviors.

---

## 6. Evidence & Forensics Products (E1–E4)

### E1. Managed Evidence Vault

- Geo-replicated, WORM-capable DigFile and ledger storage.  
- Configurable retention and legal holds.  
- Strong chain-of-custody guarantees mapped to snapshot and witness data.

### E2. Forensic Search & E-Discovery

- Structured and full-text search over DigFiles, decisions, policies, and capsules.  
- Case-oriented views grouping relevant evidence.

### E3. Incident Replay & Timeline Builder

- Time-ordered reconstruction of incidents using DigFiles and DecisionEvents.  
- Visual timelines with policy decisions, AI calls, entropy spikes, and micro-proofs.

### E4. Evidence Export & Case Bundling

- Export self-contained bundles:  
  - DigFiles, index/ledger slices, burns, policies, micro-proofs, snapshots.  
- Designed for legal teams, regulators, and external investigators.

---

## 7. Access, Portals & Integration Products (X1–X3)

### X1. Tenant Admin & Operator Console

- Main UI for security teams and operators:  
  - Policy management, cluster health, alerts, investigations.  
- Multi-tenant aware, supports RBAC and SSO.

### X2. Developer & API Gateway

- Developer-facing APIs and SDKs:  
  - Emit events, query evidence, test policies.  
- Strong authN/authZ, rate limiting, and observability.

### X3. MSSP / Partner Multi-Tenant Console

- Special view for managed security service providers and resellers.  
- Manage many customer tenants, with unified dashboards and billing.

---

## 8. Mapping Products to OSS Components

Each commercial product is deliberately anchored in one or more OSS crates:

- `utld`, `utl_cli`, `dig_mem`, `dig_index`, `security_events` → P1, P4, E1–E4, X1–X3.  
- `truthscript`, `policy_engine`, `tenant_policy`, CUE schemas → G1–G7, A1.  
- `zk_snark` → P2–P5, G1–G4, A1–A6.  
- `distillium`, `trust_container` → A4–A5, P2–P3, E3–E4.  
- `entropy_tree`, `tracer` → A2–A3, A6, E2–E3.  
- `forensics_store` → E1–E4, P1.

The **business architecture** is thus a **layered composition of open building blocks into 26 focused products**, all reinforcing Ritma’s core mission: to be the **ultimate, verifiable truth layer** for cybersecurity and AI governance.

---

## 9. Plugin Pattern for Real-World Integrations

Ritma exposes a simple, extensible plugin surface for **usage and business events** so developers can connect the truth layer to their own systems (Kubernetes, cloud billing, internal analytics, etc.) without forking the core.

### 9.1 BusinessPlugin + UsageEvent

- Core trait (in `biz_api`):
  - `BusinessPlugin`: receives `UsageEvent` structs.
  - `UsageEvent` includes `tenant_id`, `product` (one of the 26 `ProductId`s), `metric` (Decisions, DigFiles, etc.), `quantity`, and optional context (`root_id`, `entity_id`, `note`).
- Any Rust crate can implement `BusinessPlugin` to forward events into:
  - Kafka, Kinesis, Pub/Sub.
  - Internal metering pipelines.
  - Third-party billing/observability services.

### 9.2 Built-in sinks in utld

- **File sink** (`FileBusinessPlugin`):
  - Enabled by `UTLD_USAGE_EVENTS=/path/to/usage_events.jsonl`.
  - Appends one `UsageEvent` JSON line per event.
- **Stdout sink** (`StdoutBusinessPlugin`):
  - Enabled by `UTLD_USAGE_STDOUT=1`.
  - Prints each `UsageEvent` JSON line to stdout.
- **Composite sink** (`CompositeBusinessPlugin`):
  - utld combines any configured sinks so usage events can simultaneously go to files, logs, or custom plugins.

This makes it easy to hook Ritma into **Kubernetes log pipelines**, sidecar collectors, or file-based ingesters with no extra code.

### 9.3 Example integration flows

- **Kubernetes / containers**:
  - Run utld as a sidecar or DaemonSet with:
    - `UTLD_USAGE_STDOUT=1` for log-based collection.
    - And/or `UTLD_USAGE_EVENTS=/var/lib/utl/usage_events.jsonl` on a shared volume.
  - A separate agent/sidecar ships usage JSONL to the organization’s metering or analytics backend.
- **Custom Rust plugins**:
  - Vendors embed `biz_api` and implement their own `BusinessPlugin`.
  - They can replace or extend the built-in sinks via `CompositeBusinessPlugin`, wiring Ritma directly into their existing control planes and billing systems.

This plugin pattern keeps the **core enforcement and verification logic open**, while providing a clean, explicit extension point for **real-world business integrations** across any infrastructure stack.

---

## 10. Example Control Plane & Billing Flow

To make Ritma usable as a SaaS building block, an external **control plane / billing service** can be built on top of the existing code and APIs without changing the core.

### 10.1 Inputs to the control plane

- **Tenant and plan configs** (from `biz_api`):
  - `PlanConfig` / `TenantConfig` JSON files loaded via:
    - `load_plans_from_file("plans.json")`
    - `load_tenants_from_file("tenants.json")`
  - Define which `ProductId`s are enabled for each tenant and any `Quota { metric, limit }`.
- **Usage streams**:
  - `UsageEvent` JSON lines from:
    - utld via `UTLD_USAGE_EVENTS` or `UTLD_USAGE_STDOUT`.
    - HTTP via `utl_http` `POST /usage_events`.
  - Aggregated summaries via `utl_http` `GET /usage_summary`.

### 10.2 Minimal billing loop (out-of-repo service)

1. **Load configuration**:
   - On start, read plans and tenants with `biz_api` helpers.
   - Build in-memory maps: tenant → plan → enabled products/quotas.

2. **Ingest usage**:
   - Subscribe to `UsageEvent` JSONL (logs or file) and/or call `POST /usage_events` on `utl_http` for each event.
   - `utl_http` maintains in-memory totals and exposes `GET /usage_summary` for quick reads.

3. **Compute charges and quota status**:
   - On a schedule (e.g. every 5 minutes / hourly):
     - Call `GET /usage_summary` and group by tenant/product/metric.
     - For each tenant, compare usage to plan quotas.
     - Calculate billable units (e.g. decisions above free tier, extra DigFiles, storage bytes) per product.

4. **Take actions**:
   - Emit invoices or usage records to the organization’s billing system.
   - Flag tenants over quota for UI warnings or soft limits.
   - Optionally adjust configuration (e.g. disable some `ProductId`s in higher-risk overage scenarios).

5. **Expose dashboards / reports**:
   - The control plane can present per-tenant charts based on the same aggregates used for billing.
   - Because all `UsageEvent`s and evidence artifacts are verifiable with OSS tools, customers can **reconcile bills against cryptographic logs**.

This pattern separates concerns cleanly: Ritma focuses on **truthful, verifiable evidence and usage signals**, while external services implement **pricing logic, billing, and UX** using standard HTTP/JSON interfaces.
