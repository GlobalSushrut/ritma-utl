# Ritma Compliance Console Architecture

This document describes the architecture for the **Compliance Console**:

- A **compliance-as-a-machine** UI + backend where operators, engineers,
  auditors, and regulators can see and drive:
  - Burns and compliance agreements.
  - TruthScript policies and rulepacks.
  - Continuous evidence and SLOs.
- A system that feels “Vanta++ / HashiCorp++ / Cloudflare++ / Git++ for
  compliance”, but stays **infra-native and owner-controlled**:
  - Customers run it in their own infra or let Ritma host a console.
  - IDs, graphs, and evidence are owned by the org; Ritma does not become the
    central landlord for compliance state.

This builds on existing crates like `compliance_engine`, `compliance_index`,
`compliance_rulepacks`, `svc_ledger`, `security_kit`, and `truthscript`.

---

## 1. Design goals

- **Compliance as a machine, not a spreadsheet**
  - Policies and controls are executable TruthScript / rulepacks.
  - Evidence is first-class, structured, and queryable.
  - Burns encode time-bound compliance promises with cryptographic anchors.

- **Owner-controlled, infra-native**
  - All compliance graphs, burns, and evidence live in the customer’s infra by
    default (their databases, their object stores, their KMS).
  - Ritma-hosted experiences are optional layers on top (console UI,,
    reporting, billing), not the only way to run.

- **Better than SaaS point tools**
  - Vanta-like org view: controls, tests, vendor inventory, questionnaires.
  - GitHub-like: branches, diffs, reviews, history of TruthScript policies.
  - Cloudflare-like: live security pipelines and workers wiring policy to
    enforcement.
  - HashiCorp-like: infra as code and drift detection for security/controls.

- **Interoperable and exportable**
  - Everything can be exported as JSON/YAML/CSV; IDs are stable, not tied to a
    closed SaaS.
  - The same control/evidence graph can be consumed by regulators, auditors,
    and internal tooling.

---

## 2. Conceptual data model

The Compliance Console sits on top of a **compliance graph** composed of:

- **Policies**
  - TruthScript policies and policy packs (from `truthscript`, `policy_engine`).
  - Versioned, branchable, and signed (optional) using node/Cloud keys.

- **Controls & requirements**
  - Nodes representing specific controls (e.g. NIST, SOC 2, ISO 27001).
  - Linked to TruthScript policies and runtime checks that satisfy them.

- **Evidence & observations**
  - Evidence items (dig files, SLO events, configuration snapshots, logs).
  - Indexed and normalized via `compliance_index` and `forensics_store`.

- **Burns & agreements**
  - Burns created via `compliance_index::BurnProcess` and `BurnConfig`:
    - Contain `signing_key_id` and optional `auto_sign` semantics.
  - Encode a **compliance agreement** (e.g. "we will meet SLO X with
    enforcement Y for tenants in region Z") with:
    - Time window.
    - Scope of systems and tenants.
    - Expected SLOs and evidence feeds.

- **SLOs and obligations**
  - SLO records (from existing SLO/event telemetry) that track enforcement,
    drift, and violations.
  - Linked to burns, controls, and policies.

- **Actors & identity**
  - Orgs, tenants, projects, and service accounts.
  - Git-like authorship for policy changes (who edited what, when).

The console presents different **projections** of this graph for different
personas (CISO, auditor, SRE, engineer).

---

## 3. Backend architecture

### 3.1 Compliance Console Backend (CCB)

- New crate (e.g. `compliance_console_api`) with:
  - **Rust + axum + tokio**, matching `ritma_cloud` and `billing_daemon`.
  - PostgreSQL via `sqlx` (can reuse existing compliance schemas).

- Responsibilities:
  - Orchestrate **burn lifecycles** (draft → approved → active → expired).
  - Provide rich **graph APIs** over policies, controls, evidence, SLOs.
  - Implement **Git-like workflows** for policies.
  - Surface **Vanta-like control coverage** and **Cloudflare-like
    enforcement pipelines**.

### 3.2 Integration with existing crates

- **`compliance_model` / `compliance_engine`**
  - Evaluate controls and policies against evidence.
  - Compute compliance status per control, per tenant, per burn.

- **`compliance_index`**
  - Manage burns (via `BurnProcess` and `BurnConfig`).
  - Index evidence and link it to compliance artifacts.

- **`compliance_rulepacks`**
  - Library of standard control mappings (SOC 2, ISO 27001, etc.).

- **`svc_ledger`**
  - Optional anchoring of compliance material into a ledger (for strong audit
    trails and third-party attestation).

- **`security_kit` / SLO telemetry**
  - Provide enforcement SLOs and security events as evidence.

- **`ritma_cloud`**
  - Source of org/tenant metadata, keys, and high-level usage.

### 3.3 API surface (examples)

- **Policies & rulepacks**
  - `GET /api/policies` – list TruthScript policies and packs.
  - `GET /api/policies/{id}` – view policy with history and links to controls.
  - `POST /api/policies` – create new policy version.
  - `POST /api/policies/{id}/merge` – Git-like merge between branches.

- **Burns & agreements**
  - `POST /api/burns` – create a new compliance burn (draft).
  - `GET /api/burns/{id}` – see scope, commitments, and current status.
  - `POST /api/burns/{id}/activate` – trigger signing and activation.
  - `GET /api/burns/{id}/evidence` – evidence graph linked to this burn.

- **Controls & coverage**
  - `GET /api/controls` – list controls and mapped tests/policies.
  - `GET /api/controls/{id}/status` – pass/fail/unknown with evidence links.
  - `GET /api/orgs/{org_id}/compliance-summary` – high-level dashboard.

- **Evidence & SLOs**
  - `GET /api/evidence/search` – query evidence index.
  - `GET /api/slo/events` – enforcement SLO events (filtered by org/burn).

- **Git-like operations**
  - `GET /api/policies/{id}/diff?base=...&head=...` – diff between versions.
  - `POST /api/policies/{id}/review` – submit review/approval comments.

All endpoints are **org-scoped** and protected by OIDC/JWT + RBAC.

---

## 4. Frontend architecture and UX

### 4.1 Tech stack

- **Next.js (React, TypeScript)**.
- **Tailwind CSS + shadcn/ui** for fast, composable UI.
- **React Query** for data fetching and caching.
- **Graph-like visualizations** using libraries such as Vis.js or Cytoscape.js
  for control/evidence graphs.

### 4.2 Key UI surfaces

1. **Compliance Command Center** (CISO / VP Security)
   - Overall compliance score per framework (SOC 2, ISO, custom).
   - Active burns with status (on-track, at risk, violated).
   - Heatmap of controls vs org units / tenants.
   - Timeline of significant compliance events.

2. **Burns & Agreements view**
   - List of burns, their scopes, and SLOs.
   - Detail page:
     - Textual representation of the agreement.
     - Linked policies, controls, and evidence streams.
     - Status bar showing current compliance posture.

3. **Policy (TruthScript) workspace** – Git-like
   - Repositories / workspaces for policy packs.
   - Branches, pull requests, reviews, and diffs for TruthScript.
   - Inline evaluation results (e.g. "this change affects controls X, Y").
   - Visual dependency graph from policies → controls → burns.

4. **Controls & tests (Vanta-like)**
   - Catalog of controls with mappings to frameworks.
   - For each control:
     - Status (pass/fail/partial), evidence sources, responsible owner.
   - Gaps and drift detection (e.g. control expected N nodes/environments,
     but only M actually instrumented).

5. **Security pipelines (Cloudflare-like)**
   - Visualization of policy-enforced data paths:
     - E.g. code → CI → deploy → runtime → evidence.
   - Per-pipeline enforcement status:
     - Are policies applied? Are SLOs met? Any exceptions?
   - Drill-down to specific nodes or services.

6. **Engineer view**
   - Focused on "what do I need to fix?":
     - Open compliance tasks per repo/service.
     - Policies failing against my environment.
   - Git-like integration (status reported back into GitHub/GitLab via checks).

7. **Regulator / auditor view**
   - Read-only, time-bounded access to burns, evidence graphs, and control
     status.
   - Exportable reports and machine-readable attestations.

---

## 5. Ownership, identity, and federation

- **Org-owned compliance graph**
  - Each org has its own graph rooted in its own DB/ledger.
  - IDs are stable URNs/UIDs, not SaaS-specific opaque IDs.

- **Federated views**
  - Ritma-hosted consoles can query multiple org graphs (with consent) to
    provide multi-tenant visibility for MSSPs or regulators.
  - Still, underlying evidence and burns remain owned by the originating orgs.

- **Democratized control**
  - Everything is scriptable and exportable; an org can:
    - Fork rulepacks and policy repos.
    - Run its own Compliance Console.
    - Build its own visualizations via APIs.

---

## 6. Implementation roadmap

1. **Core APIs & graph**
   - Stand up `compliance_console_api` with health/auth.
   - Expose read-only views over existing compliance models and burns.

2. **Burn lifecycle**
   - Implement full CRUD + state transitions for burns.
   - Integrate signing with node/Cloud keys (using `node_keystore` and
     `ritma_cloud` key governance).

3. **Policy Git-like workflows**
   - Build TruthScript workspace management, branching, and diff endpoints.
   - Implement basic PR/review flows.

4. **Controls, coverage, and Vanta-like overview**
   - Map rulepacks to controls and frameworks.
   - Compute and display coverage and gaps.

5. **Pipelines & security flows**
   - Integrate CI/CD and runtime telemetry into visual pipelines.
   - Show where policies and SLOs are enforced across the stack.

6. **Auditor/regulator surfaces**
   - Build read-only, time-bounded portal views.
   - Add export formats and ledger anchoring hooks.

7. **Hardening & scale**
   - Optimize graph queries.
   - Add caching, pagination, and multi-org federation.

The Compliance Console thus becomes an **infra-native, owner-controlled**
compliance machine that can rival and eventually exceed point SaaS tools like
Vanta, while being rooted directly in the runtime, evidence, and policy
execution already present in the Ritma stack.
