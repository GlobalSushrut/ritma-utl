# Ritma Billing & Payment Architecture

This document describes how Ritma can turn the existing **open-core + 26 products**
model into a working **billing and payment system**. It focuses on:

- How to bundle products into **Free / Standard / Enterprise** plans.
- How to use existing **UsageEvent** and **MetricKind** types for metering.
- How a **cloud-side billing engine** and a **hosted billing website** fit
  alongside customer-hosted `ritma_cloud`.

The goal is to have a clear, incremental path from todays repo to a
production-grade billing stack.

---

## 1. Goals and constraints

- **Open core stays free**
  - `utld`, `utl_cli`, TruthScript, dig/index, zk, etc. remain OSS.
  - Billing is about **managed services and products**, not locking formats.

- **Customer-hosted `ritma_cloud` is first-class**
  - `ritma_cloud` in this repo is **just code** and containers that customers
    deploy into their own infrastructure (their cloud accounts, their
    Kubernetes clusters, their PostgreSQL instances).
  - Many customers will run `ritma_cloud` themselves (on-prem, VPC, air‑gapped).
  - Ritma-operated billing systems **must not require** that we operate
    the customer’s control plane.

- **No customer evidence/keys stored by Ritma by default**
  - All DigFiles, evidence summaries, keys, SLOs, and logs live inside the
    customer‑hosted `ritma_cloud` + `utld` stack.
  - Ritma‑hosted services only ever see **minimal usage aggregates and
    billing metadata**, and only if the customer opts into using Ritma’s
    billing service.

- **Ritma-hosted billing website**
  - Ritma operates a small SaaS web app (e.g. `billing.ritma.io`).
  - It handles account onboarding, plan selection, payment methods, and
    usage/billing views.
  - It never connects directly to customer DigFiles or evidence; it only
    consumes usage aggregates or `UsageEvent` streams that the customer
    chooses to send.

- **Metering-first, not lock-in**
  - All usage is derived from **UsageEvent** and summary endpoints that
    can be exported by the customer.
  - Customers can still reconcile bills by re-running usage aggregation
    locally from the same events.

---

## 2. Domain model (products, metrics, plans)

### 2.1 Products and metrics (from code)

`crates/biz_api/src/lib.rs` already defines the core economic primitives:

- **Products**: `ProductId` (26 commercial SKUs)
  - Platform & Witnessing (P19)
  - Policy & Governance (G17)
  - AI & Behavioral Security (A16)
  - Evidence & Forensics (E14)
  - Access, Portals & Integrations (X13)

- **Metered dimensions**: `MetricKind`
  - `Decisions`  count of `DecisionEvent`s.
  - `DigFiles`  count of sealed DigFiles.
  - `StorageBytes`  logical bytes stored.
  - `SnapshotExports`  count of snapshot exports.
  - `ApiCalls`  API calls into Ritma Cloud.

- **Usage events**: `UsageEvent`
  - `(tenant_id, product: ProductId, metric: MetricKind, quantity: u64, ...)`
  - Today emitted by `utld` via `BusinessPlugin` hooks for decisions and dig
    sealing.

This means **no new Rust types are required** for basic metering.

### 2.2 Plans and bundles

`biz_api` also defines **plan configuration** types:

- `PlanTier`  `Community`, `Team`, `Enterprise`, `Sovereign`, `Custom { label }`.
- `Quota`  `{ metric: MetricKind, limit: Option<u64> }`.
- `PlanProductConfig`  `{ product: ProductId, enabled: bool, quotas: Vec<Quota> }`.
- `PlanConfig`  `{ plan_id: String, tier: PlanTier, products: Vec<PlanProductConfig> }`.
- `TenantConfig`  ties a `tenant_id` to a `PlanConfig`.

Plans can be loaded from JSON via `load_plans_from_file` and
`load_tenants_from_file`.

#### 2.2.1 Free / Pilot plan (Community tier)

- **Plan ID:** `pilot_free`
- **Tier:** `PlanTier::Community`
- **Products enabled (subset):**
  - `ManagedUtldClusters`
  - `ComplianceReportingEngine`
  - `LawbookControlLibrary`
  - `ManagedEvidenceVault`
  - `EvidenceExportBundling`
  - `TenantAdminConsole`
- **Quotas (per tenant, per month  example numbers):**
  - `Decisions`: 100k
  - `DigFiles`: 1k
  - `StorageBytes`: 100 GB
  - `SnapshotExports`: 20
  - `ApiCalls`: 100k
- **Pricing:** base MRR = **$0**, overages ideally **not billed** (hard caps).

#### 2.2.2 Standard plan (Team tier)

- **Plan ID:** `standard`
- **Tier:** `PlanTier::Team`
- **Products enabled (core commercial set):**
  - All of the above, plus most P1P6, G1G4, E1E4, X1X2.
- **Quotas (per tenant, per month  example):**
  - `Decisions`: 5M
  - `DigFiles`: 50k
  - `StorageBytes`: 2 TB
  - `SnapshotExports`: 200
  - `ApiCalls`: 2M
- **Pricing:**
  - Base MRR `B_std` (e.g. $3k/month).
  - Overages per-metric (see Section 4.3).

#### 2.2.3 Enterprise plan (Enterprise/Sovereign tier)

- **Plan ID:** `enterprise`
- **Tier:** `PlanTier::Enterprise` or `Sovereign`.
- **Products enabled:** all 26 `ProductId` values.
- **Quotas (per tenant, per month  example):**
  - `Decisions`: 50M
  - `DigFiles`: 500k
  - `StorageBytes`: 20 TB
  - `SnapshotExports`: 2,000
  - `ApiCalls`: 20M
- **Pricing:**
  - Base MRR `B_ent` (e.g. $12k/month).
  - Discounted overage rates vs Standard.

A `plans.json` file can encode these three `PlanConfig` objects and be loaded by
billing services.

---

## 3. Metering pipeline (from code to bills)

### 3.1 Event emission (data plane / utld)

Today:

- `utld` emits `UsageEvent` records via `BusinessPlugin`:
  - On each `DecisionEvent` (with tenant_id): metric `Decisions`.
  - On each sealed DigFile (with tenant_id): metric `DigFiles`.
- Implementations shipped in the repo:
  - `FileBusinessPlugin`: appends JSONL lines to a file path.
  - `StdoutBusinessPlugin`: prints JSON for local analytics.

**Next step for billing:**

- Add a **`HttpBusinessPlugin`** that POSTs `UsageEvent` to a
  **Ritma Billing Ingest API** (hosted by Ritma).
- Alternatively, for self-hosted-only customers, they can configure
  `FileBusinessPlugin` and periodically upload the JSONL files to Ritma
  (or process locally and send aggregates).

### 3.2 Aggregation (billing control plane)

We introduce a logical **Billing Aggregator** service (new component, not yet
implemented) with responsibilities:

- Accept `UsageEvent` via HTTPS ingest.
- Normalize and deduplicate events.
- Aggregate usage into **(tenant, product, metric, time_bucket)** keys.

Data model (conceptual):

- `usage_events_raw` table (append-only).
- `usage_aggregates_monthly` table with columns:
  - `tenant_id`, `plan_id`, `product`, `metric`, `year_month`, `quantity`.

Aggregation job (daily cron or streaming):

- Reads new `UsageEvent` rows.
- Looks up `TenantConfig` to attach `plan_id`.
- Updates `usage_aggregates_monthly`.

For customers running `ritma_cloud` themselves, two options:

1. **Push mode:** they POST their aggregated usage to Ritma Billing using a
   documented API.
2. **Pull mode (optional, more complex):** Ritma Billing can read `usage_summary`
   or `org_usage` from the customers exposed `ritma_cloud` endpoint, if they
   allow it.

---

## 4. Billing engine and MRR calculation

### 4.1 New pricing config layer

To turn usage into revenue, we define a **pricing config** (separate from plans):

- **Keyed by**: `(plan_id, metric: MetricKind)`.
- **Fields:**
  - `included_per_month: u64` (mirrors Quota but lives in billing).
  - `price_per_unit_over: f64`.
  - `unit_description: String` (e.g. "per 10k decisions").

Example (YAML/JSON, conceptual):

```yaml
- plan_id: pilot_free
  metric: decisions
  included_per_month: 100000
  price_per_unit_over: 0.0
  unit_description: "per decision (hard capped, no overage)"
- plan_id: standard
  metric: decisions
  included_per_month: 5000000
  price_per_unit_over: 0.40   # $0.40 per 10k decisions (see unit scaling)
  unit_description: "per 10k decisions"
- plan_id: enterprise
  metric: decisions
  included_per_month: 50000000
  price_per_unit_over: 0.25
  unit_description: "per 10k decisions"
```

The billing engine can either:

- Treat `quantity` **in whole units** (e.g. 1 = 10k decisions), or
- Apply a scaling factor when computing overages.

### 4.2 Invoice and subscription model

Conceptual entities for billing (Ritma-hosted DB):

- `CustomerAccount`
  - External ID (matches org or tenant in `ritma_cloud`).
  - Contact info, legal entity, billing address.
  - Mapping to payment provider (e.g. Stripe customer ID).

- `Subscription`
  - `customer_id`, `plan_id`, `status` (active/canceled/trial), `start_at`, `end_at`.

- `Invoice`
  - `customer_id`, `period_start`, `period_end`, `status` (draft/issued/paid).
  - One-to-many `InvoiceLineItem` records.

- `InvoiceLineItem`
  - `product`, `metric`, `quantity`, `unit_price`, `amount`.

### 4.3 MRR calculation (min/max bands)

For a given subscription `S` on plan `P` for month `M`:

1. Fetch aggregated usage:
   - For each `(product, metric)` pair, get `usage_aggregates_monthly` row
     with `quantity = q(P,metric)`.
2. Fetch pricing config for `plan_id = P.plan_id` and `metric`.

For each metric `m`:

- Included quota: `Q_m` (from pricing config or PlanConfig/Quota).
- Actual usage: `U_m`.
- Billing unit scaling: `scale_m` (e.g. 1 unit = 10k decisions).
- Unit price: `P_m` (price per billing unit over quota).

Then:

```text
over_units_m = max(0, (U_m - Q_m) / scale_m)
overage_amount_m = over_units_m * P_m
```

Total invoice amount:

```text
invoice_amount = base_price(P) + sum_m overage_amount_m
```

Where `base_price(P)` is:

- `0` for `pilot_free`.
- e.g. `$3,000` for `standard`.
- e.g. `$12,000` for `enterprise`.

**MRR_min** for a plan (light-usage tenant):

- Usage stays below quotas for all metrics.
- `MRR_min(P) = base_price(P)`.

**MRR_max** for a plan (within a target band, e.g. 3x quotas):

- Pick design maximums `U_m_max` (e.g. `3 * Q_m`).
- Compute `invoice_amount` using `U_m = U_m_max`.

This produces a practical **band** for each plan:

- Standard: e.g. `$3k  $10k+/month`.
- Enterprise: e.g. `$12k  $40k+/month`.

---

## 5. Payment provider integration

To collect cash, the billing engine integrates with an external provider
(e.g. Stripe, Paddle, Braintree). Design goals:

- **Ritma never stores raw card data.**
- Provider acts as the source of truth for:
  - Payment methods.
  - Charge attempts and status.
  - Refunds and disputes.

Minimum integration:

- `CustomerAccount` stores provider customer ID.
- `Subscription` optionally stores provider subscription ID.
- Invoices can either:
  - Be mirrored into the provider for charging, or
  - Be rendered by Ritma and paid via provider-hosted checkout/portal.

Webhooks from the provider update invoice and subscription status (paid, failed,
canceled) in Ritma Billing.

---

## 6. Hosted billing website (UI)

Ritma operates a small web app (e.g. Next.js + Tailwind) at
`https://billing.ritma.io`. This is separate from any customer-hosted
`ritma_cloud` instances.

### 6.1 Target personas

- **New prospects** evaluating the platform.
- **Operators** at existing customers managing their subscriptions.
- **Finance / procurement** teams at customers reviewing invoices and usage.

### 6.2 Key pages and flows

1. **Marketing & plan comparison**
   - Public pages comparing:
     - Free / Pilot
     - Standard
     - Enterprise (and Sovereign variants)
   - Tables listing included products and headline quotas.

2. **Self-service signup / login**
   - Create a **Ritma Billing Account** (email + OIDC/SSO optional).
   - Link to an existing `org_id` / `tenant_id` in `ritma_cloud`, or
     register a new org.

3. **Plan selection / upgrade / downgrade**
   - Choose between `pilot_free`, `standard`, `enterprise`.
   - For paid plans:
     - Collect billing details and payment method (via provider components).
     - Create `Subscription` and initial `Invoice`.

4. **Usage & cost dashboard**
   - For a given tenant/org:
     - Show monthly graphs for key metrics:
       - `Decisions`, `DigFiles`, `StorageBytes`, `SnapshotExports`, `ApiCalls`.
     - Indicate included quota vs actual usage.
     - Estimate current-month spend (pro-rated) based on pricing config.

5. **Invoice & payment history**
   - List all invoices (draft, issued, paid, failed).
   - Downloadable PDFs / CSV exports.
   - Links to provider-hosted receipt pages.

6. **Account settings**
   - Manage billing contacts.
   - Update payment methods (via provider components).
   - Configure invoice email recipients and PO numbers.

### 6.3 Integration with customer-hosted `ritma_cloud`

Because many customers self-host `ritma_cloud`, the billing website interacts
with usage in two modes:

- **Vendor-hosted control plane**
  - Ritma operates `ritma_cloud` for the customer (multi-tenant SaaS).
  - Billing engine reads usage directly from shared `UsageEvent` ingest.

- **Customer-hosted `ritma_cloud`**
  - Customer runs control plane; Ritma Billing only sees:
    - Usage events pushed via `HttpBusinessPlugin`, or
    - Periodic aggregated summaries they upload or expose.
  - Plan mapping still happens via `TenantConfig` + a small exported mapping.

In both cases, the billing site displays **the same UX**, but the data source
for usage differs behind the scenes.

---

## 7. Security and data minimization

- Usage data contains **tenant IDs and product/metric labels**, not raw secrets.
- Billing DB stores **amounts and invoice meta**, but never card numbers.
- All provider interactions go through tokenized IDs.
- Export formats (CSV/JSON) are bounded and documented so customers can
  reconcile charges.

---

## 8. Implementation roadmap

A realistic phased rollout:

1. **Phase A: Internal metering & manual billing**
   - Use existing `FileBusinessPlugin` to log `UsageEvent` JSONL.
   - Build a small script or CLI to aggregate usage into CSV.
   - Manually issue invoices from spreadsheets.

2. **Phase B: Billing aggregator + hosted billing UI (no auto-charges)**
   - Implement Billing Aggregator API and `usage_aggregates_monthly` tables.
   - Stand up `billing.ritma.io` with:
     - Auth, plan comparison, usage dashboard, invoice export.
   - Still collect payment via manual wires/cards.

3. **Phase C: Payment provider integration**
   - Integrate Stripe (or equivalent) for card/ACH.
   - Add full invoice life cycle (draft  issued  paid/failed).
   - Enable automatic charging on billing cycles.

4. **Phase D: Advanced packaging & resellers**
   - Support Sovereign and MSSP tiers.
   - Add partner billing workflows and revenue sharing.

Throughout all phases, the OSS core and `ritma_cloud` remain deployable without
any billing components; the billing system is an **adjacent, optional** Ritma
service that uses the same UsageEvent vocabulary as the open source stack.
