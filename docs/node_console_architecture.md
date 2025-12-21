# Ritma Node Console Architecture

This document describes the architecture and tech stack for the **Node Console**
("nodes console"). The Node Console is the tenant/operator-facing control
plane for managing `utld` runtime nodes, viewing their health and security
posture, and understanding runtime usage and costs.

The design keeps to Ritma's principles:

- `ritma_cloud`, `utld`, and evidence live in **customer-owned
  infrastructure**.
- Ritma may operate an optional **hosted Node Console** service
  (backend + frontend) that talks to customer `ritma_cloud` in a limited,
  controlled way, or customers can self-host the console.
- Billing is wired via the existing **UsageEvent / ProductId / MetricKind**
  types and the **billing_daemon** service.

---

## 1. Goals and scope

The Node Console provides:

- **Node inventory & health**
  - List and search all nodes per org/tenant.
  - Status: online/offline, last heartbeat, UTLD version, policy version.

- **Security & governance visibility**
  - Per-node view of recent enforcement decisions (allow/deny/throttle/isolate).
  - Integration with Cloud key governance (which keys a node uses, status).
  - SLO metrics per node and per tenant (from existing SLO logging and
    `ritma_cloud`/SLO tables).

- **Usage & cost awareness**
  - Runtime usage by metric (`Decisions`, `DigFiles`, etc.).
  - Optional integration with the billing system to show estimated monthly
    spend per tenant using the `billing_daemon` invoice drafts.

- **Runtime configuration assist**
  - Node enrollment tokens.
  - UTLD configuration templates (env vars, TLS, governance flags) per org.

The console **does not**:

- Store or display raw evidence payloads or private keys.
- Replace `ritma_cloud` APIs; instead, it calls them as a read/write client
  with scoped access.

---

## 2. High-level architecture

### 2.1 Components

- **Node Console Backend (NCB)**
  - New Rust service (separate crate, e.g. `node_console_api`).
  - Exposes REST/JSON APIs for the frontend.
  - Talks to:
    - `ritma_cloud` for org/tenant/nodes/keys/SLO summaries.
    - `billing_daemon` for usage and invoice drafts (optional, read-only).

- **Node Console Frontend (NCF)**
  - TypeScript React app (Next.js).
  - Hosted by Ritma at `https://console.ritma.io` or self-hosted by customers.
  - Uses NCB APIs and integrates with IdP (OIDC).

- **Existing services**
  - `ritma_cloud`: source of truth for orgs, tenants, keys, governance,
    SLO aggregates.
  - `utld`: emits `UsageEvent` via `BusinessPlugin` hooks.
  - `billing_daemon`: aggregates usage and computes invoice drafts using
    `biz_api` billing logic.

Arrows:

```text
utld (customer infra) --> ritma_cloud           (customer infra)
                     --> billing_daemon        (Ritma infra, optional)

Node Console Frontend --> Node Console Backend --> ritma_cloud
                                           \--> billing_daemon (optional)
```

### 2.2 Deployment models

- **Ritma-hosted console**
  - Ritma deploys NCB + NCF in its own cloud.
  - Customers either:
    - Expose limited `ritma_cloud` APIs over mutually-authenticated TLS; or
    - Push summary data (nodes, SLOs, usage) into a Ritma-hosted shadow view.

- **Customer-hosted console**
  - Customer runs NCB + NCF inside their own VPC/on-prem.
  - NCB talks directly to their internal `ritma_cloud` and optional
    `billing_daemon` instance.
  - No data leaves their perimeter unless they also opt into Ritma billing.

---

## 3. Backend (Node Console API) design

### 3.1 Tech stack

- **Language:** Rust.
- **Framework:** `axum` + `tokio` (matching `ritma_cloud` and `billing_daemon`).
- **DB:** PostgreSQL via `sqlx` or reuse `ritma_cloud` DB with a narrower
  schema access layer.
- **Config:** `ENV`-driven (console base URL, upstream endpoints, IdP info).

### 3.2 Authentication & authorization

- **Auth:**
  - OIDC/JWT-based authentication.
  - NCB verifies bearer tokens using JWKS from the IdP.
  - Claims: user id, email, org memberships, roles.

- **RBAC:**
  - Roles per org: `org_owner`, `org_admin`, `viewer`, `support`.
  - Policies:
    - `viewer`: read-only access to nodes, SLOs, usage.
    - `org_admin`: can manage node enrollment tokens, toggle governance
      settings (where allowed).
    - `org_owner`: can change plans (link out to billing site) and approve
      console-wide settings.

### 3.3 External integrations

- **With `ritma_cloud`**
  - NCB acts as a client of `ritma_cloud` REST APIs:
    - `GET /orgs/{org_id}/nodes` (existing or added) for node inventory.
    - `GET /orgs/{org_id}/keys` and `GET /keys/{key_id}` for key governance.
    - `PATCH /keys/{key_id}/governance` for status updates (admin-only).
    - `GET /orgs/{org_id}/keys/summary` for governance roll-ups.
    - `GET /orgs/{org_id}/usage` or similar summary endpoint for top-level
      runtime stats.

- **With `billing_daemon`** (optional)
  - For cost views only; never required for basic operation.
  - Endpoints:
    - `GET /invoice-draft?tenant_id=...&period_idx=...` for current-period
      estimated invoice.
  - NCB may cache/resample these values to avoid overloading the daemon.

### 3.4 API surface (examples)

Examples of NCB endpoints (to be refined in implementation):

- **Auth/session**
  - `GET /api/me` → current user profile, orgs, roles.

- **Nodes**
  - `GET /api/orgs/{org_id}/nodes`
  - `GET /api/orgs/{org_id}/nodes/{node_id}`
  - `GET /api/orgs/{org_id}/nodes/{node_id}/events` – recent SLO/decision events.

- **Keys & governance**
  - `GET /api/orgs/{org_id}/keys` (filters: status, tenant, key label).
  - `GET /api/keys/{key_id}`
  - `PATCH /api/keys/{key_id}/governance` → forwards to `ritma_cloud`, with
    RBAC enforcement.

- **Usage & cost**
  - `GET /api/orgs/{org_id}/usage/summary` – aggregated runtime metrics.
  - `GET /api/orgs/{org_id}/billing/estimate` – calls `billing_daemon` and
    returns a high-level view of the `InvoiceDraft`.

- **Configuration & enrollment**
  - `POST /api/orgs/{org_id}/nodes/enrollment-tokens`
  - `GET /api/orgs/{org_id}/nodes/config-template` – returns a templated
    UTLD/`security_kit` config snippet.

---

## 4. Frontend (Node Console UI) design

### 4.1 Tech stack

- **Framework:** Next.js (React, TypeScript).
- **Styling:** Tailwind CSS + shadcn/ui component library.
- **Data fetching:**
  - REST via `fetch` or Axios, wrapped with TanStack Query (React Query).
- **Auth:**
  - NextAuth or custom OIDC client to obtain JWTs for NCB.

### 4.2 Key pages and UX flows

1. **Sign-in & org selection**
   - OIDC sign-in.
   - If user has multiple orgs, choose active org.

2. **Org dashboard**
   - Cards: `Active nodes`, `Policy drift`, `Key issues`, `Recent denies`.
   - Charts:
     - Decisions over time.
     - Dig files over time.
     - SLO events by type (allow/deny/throttle/isolate).

3. **Nodes list**
   - Table filtered by tenant, policy version, status.
   - Columns: node name/ID, tenant, status, UTLD version, last seen, policy
     version.

4. **Node detail page**
   - Node metadata.
   - Recent SLO/decision events timeline.
   - Key(s) used for signing, with link to key governance view.
   - Configuration snippet for replicating node setup.

5. **Keys & Governance**
   - Table of keys for org: status, rotation info, last use.
   - Actions (admin-only): set status to `active`/`revoked`/`compromised`.
   - Warnings when nodes are using keys that are revoked/expired.

6. **Usage & cost (optional)**
   - Graphs of `Decisions`, `DigFiles`, `StorageBytes`, `SnapshotExports`.
   - If billing integration is enabled:
     - Current period estimated cost from `InvoiceDraft`.
     - Breakdown by metric.

7. **Configuration & enrollment**
   - Generate enrollment tokens for new nodes.
   - Show UTLD configuration templates with correct:
     - `UTLD_SOCKET`, `UTLD_TLS_ADDR`.
     - `UTLD_USAGE_HTTP_URL` pointing to billing daemon (if enabled).
     - `RITMA_CLOUD_URL` and governance env vars.

---

## 5. Data and security considerations

- **Data minimized**
  - NCB stores only metadata: nodes, SLO counters, key status, usage
    aggregates, and UI configuration.
  - No raw evidence, dig payloads, or private keys should flow through NCB.

- **Network boundaries**
  - When Ritma hosts NCB, calls from NCB to customer `ritma_cloud` should use
    mTLS and be limited to the API surface required by the console.
  - Customers can choose to keep NCB entirely inside their own perimeter.

- **Auditing**
  - All governance changes (key status updates, enrollment token creation)
    should generate audit logs, ideally also emitting `security_kit::slo`
    events for enforcement telemetry.

---

## 6. Implementation roadmap

1. **Skeleton & auth**
   - Create `node_console_api` crate.
   - Implement `/healthz` and `/api/me` (mock data initially).
   - Stand up Next.js frontend with login and basic layout.

2. **Node inventory & health**
   - Add `GET /api/orgs/{org_id}/nodes` and `/nodes/{node_id}`.
   - Connect to `ritma_cloud` nodes table or equivalent.
   - Build Nodes list/detail pages.

3. **Governance integration**
   - Proxy Cloud key governance APIs via NCB with RBAC.
   - Build Keys & Governance UI.

4. **Usage & cost view**
   - Wire read-only integration to `billing_daemon`.
   - Display runtime usage graphs and estimated cost.

5. **Configuration & enrollment**
   - Implement enrollment tokens + config template endpoints.
   - Build UI wizard for onboarding new nodes.

6. **Hardening & packaging**
   - Add audit logging, rate limiting, and security reviews.
   - Document deployment patterns for Ritma-hosted vs customer-hosted
     consoles.

---

## 7. Daemon + Node Controller + Node Console (Deep Plan)

This section refines the Node Console into three concrete components you can
implement step by step:

- **Node Daemon** – OS-level agent that runs on each node, fetches policies,
  runs connectors, and emits evidence/SLOs.
- **Node Controller API** – central backend service that tracks nodes,
  assignments, and telemetry, and feeds the UI.
- **Node Console UI** – Next.js app (e.g. `ui/node_console`) that presents
  node state, policies, connectors, and SLOs.

### 7.1 Goals and threat model

- Treat each node as a **secure compliance appliance**:
  - Node daemon enforces policies and emits evidence & SLO events.
  - Policies are Git/TruthScript-based, not a black-box SaaS.
- Integrate with existing compliance pipelines:
  - Node events ultimately feed `UTLD_COMPLIANCE_INDEX`, dig index,
    and burns.
- Security assumptions:
  - Nodes can be compromised; the daemon must authenticate the
    controller (mTLS or signed configs) and minimize persisted secrets.
  - Controller must authenticate nodes (per-node identities, narrow
    scopes per org/tenant).

### 7.2 Node Daemon (OS agent)

**Crate:** `crates/node_daemon` (Rust binary, e.g. `ritma-node-daemon`).

**Responsibilities:**

1. **Identity & registration**
   - On first start:
     - Generate node UID (reuse `UID` from `core_types`).
     - Create or load node keypair/HMAC key from local keystore
       (`RITMA_KEYSTORE_PATH`).
     - Persist identity to `/var/lib/ritma-node/identity.json`.
   - Register with Node Controller:
     - `POST /api/nodes/register` with org/tenant, hostname, labels,
       capabilities.

2. **Config & policy sync**
   - Periodically call `GET /api/nodes/{node_id}/policies` to fetch
     assigned rulepacks and enforcement mode.
   - Cache rulepacks/policies under
     `/var/lib/ritma-node/policies/` and verify hashes.

3. **Connectors and controllers**
   - Load connector configs (Kubernetes, AWS, GCP, storage, etc.) from
     either local YAML or `GET /api/nodes/{node_id}/connectors`.
   - Invoke existing `security_kit` connectors in dry-run mode to
     evaluate posture.

4. **Telemetry and evidence**
   - Emit:
     - Compliance events (control evals) into JSONL that feed
       `UTLD_COMPLIANCE_INDEX`.
     - Evidence dig files via `utld` / `dig_index` pipeline.
     - SLO events (via `security_kit::observability::emit_slo_event`).
   - Optionally push summarized SLO telemetry to Node Controller.

5. **Heartbeats & health**
   - Periodic heartbeat:
     - `POST /api/nodes/{node_id}/heartbeat` with status, version,
       last policy sync, last evidence batch time, SLO counters.

**Key env/config:**

- `RITMA_NODE_CONTROLLER_URL` – Node Controller base URL.
- `RITMA_NODE_ORG_ID`, `RITMA_NODE_TENANT_ID` – routing scope.
- `RITMA_KEYSTORE_PATH`, `RITMA_KEY_ID` – local keystore integration.

### 7.3 Node Controller API

**Crate:** `crates/node_controller_api` (Rust, Axum + Tokio).

This service is the central control plane for nodes. It should be
multi-tenant and share auth/RBAC patterns with `compliance_console_api`.

**Core data model (conceptual):**

- `Node` – identity and status
  - `id: UID`, `org_id`, `tenant_id`
  - `hostname`, `labels: BTreeMap<String, String>`
  - `status: online/offline/degraded`
  - `last_heartbeat_at`, `utld_version`, `policy_version`

- `NodePolicyAssignment`
  - `node_id`, `rulepack_ids: Vec<String>`, `frameworks`
  - `enforcement_mode: observe | enforce`

- `ConnectorConfig`
  - `node_id`, `connector_type` (e.g. `k8s`, `aws`, `gcp`, `storage`)
  - `params: ParamBag` or typed structs per connector

- `NodeSloSummary`
  - Aggregated SLO counts by component/operation/outcome.

**APIs (high-level):**

- **Node lifecycle**
  - `POST /api/nodes/register` – called by daemon on first start.
  - `POST /api/nodes/{id}/heartbeat` – periodic health/summary.
  - `GET /api/nodes` – list nodes for UI (filter by org/tenant).
  - `GET /api/nodes/{id}` – node details.

- **Policy assignment**
  - `GET /api/nodes/{id}/policies` – rulepacks and frameworks
    assigned to this node.
  - `POST /api/nodes/{id}/policies` – set or update assignments
    (operator-facing, RBAC-protected).

- **Connectors**
  - `GET /api/nodes/{id}/connectors` – current connector configs.
  - `POST /api/nodes/{id}/connectors` – add/update connectors.
  - Optional trigger: `POST /api/nodes/{id}/connectors/{cid}/dry-run`.

- **Telemetry**
  - `POST /api/nodes/{id}/slo` – ingest summarized SLO events (if
    not going directly to `ritma_cloud`).
  - `GET /api/nodes/{id}/slo-summary` – read-only for UI.
  - `GET /api/nodes/{id}/events` – recent enforcement/incident
    summaries (no raw payloads).

**Auth & RBAC:**

- Node → controller:
  - mTLS or signed JWT using node keystore key.
  - Scope to `{org_id, tenant_id, node_id}`.
- Human → controller (UI/API):
  - Use existing OIDC/JWT validation patterns.
  - Roles: `org_owner`, `org_admin`, `node_admin`, `viewer`.

### 7.4 Node Console UI (Next.js)

**App:** `ui/node_console` (Next.js + TypeScript).

**Key pages:**

1. `/nodes` – Node inventory
   - Table columns: node ID/hostname, org/tenant, status,
     UTLD version, last heartbeat, policy version, connector count.
   - Filters by org, tenant, label, status.

2. `/nodes/{id}` – Node detail
   - Node metadata panel.
   - Policy assignment panel (active rulepacks + enforcement mode,
     link to Compliance Console `/policies`).
   - Connectors panel: list connectors, last dry-run status.
   - Telemetry panel: recent SLO events and enforcement summaries.

3. `/connectors` (optional cross-node view)
   - All connectors grouped by type, with health and last run.

**Integration:**

- Configured via `NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL`.
- Reuse header-based stub auth in dev (`x-user-id`, `x-org-id`, `x-roles`).
- Long term, align auth with Compliance Console (shared login & roles).

### 7.5 Phased implementation checklist

You can implement this in phases:

1. **Phase 1 – Skeletons**
   - Create `node_controller_api` with:
     - `/healthz`, `/api/me` (mocked), `POST /api/nodes/register`,
       `POST /api/nodes/{id}/heartbeat`, `GET /api/nodes`.
   - Create `node_daemon` that:
     - Generates identity, registers once, sends periodic heartbeat.
   - Create `ui/node_console` with `/nodes` table calling
     `GET /api/nodes`.

2. **Phase 2 – Policy assignment & connectors**
   - Implement `NodePolicyAssignment` and related APIs.
   - Wire daemon to consume `GET /api/nodes/{id}/policies` and cache
     rulepacks.
   - Add basic connectors config endpoints and show them in the UI.

3. **Phase 3 – Telemetry & evidence**
   - Hook daemon into `security_kit` and `security_host` to emit SLO
     and enforcement events.
   - Decide whether SLOs go directly to `ritma_cloud` or via Node
     Controller, and update APIs accordingly.
   - Ensure compliance events flow into `UTLD_COMPLIANCE_INDEX` and
     are visible in the Compliance Console.

4. **Phase 4 – Deep UI integration**
   - Enrich Node Console with detailed views, charts, and links into
     Compliance Console (burns, evidence search, policies).

5. **Phase 5 – Hardening & packaging**
   - Add mTLS/JWT validation for node → controller.
   - Implement robust RBAC for operators.
   - Package daemon as a systemd service and publish deployment docs.

Use this section as the implementation guide for the hardest pieces:
the OS daemon, node controller backend, and Node Console front-end.
