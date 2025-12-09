# Ritma Business Model – Open Core + SaaS "Truth Layer"

> Draft: how Ritma can be a **free, verifiable core** plus a **global SaaS truth layer** for cybersecurity and AI governance.

---

## 1. Positioning

Ritma aims to be a **Universal Truth Layer for Security**:

- A cryptographically verifiable substrate under logs, policies, and AI activity.
- Stronger guarantees than today’s SIEMs / logging pipelines, without requiring a blockchain.
- Open formats and open-source core so anyone can **run, verify, and extend** the system.

The business model is **open core + multi-tenant SaaS**:

- The **core engine** (utld, TruthScript, dig format, zk circuits, CLI, CUE schemas) is free and open.
- A **hosted Ritma Cloud** adds:
  - Global witness and anchoring infrastructure.
  - Enterprise control plane, dashboards, and compliance packs.
  - Long-term evidence storage and operations support.

The litmus test: an enterprise should be able to **prove critical properties offline** (using the FOSS core) while still buying Ritma Cloud for scale, reliability, and global assurances.

---

## 2. What Stays Free and Open Core

### 2.1 Free OSS Core Scope

The following capabilities are **always free and open-source**:

- **Core engine and data model**
  - `utld` daemon and `utl_cli`.
  - `truthscript` policy language and `policy_engine` semantics.
  - `tenant_policy` and event/dig schemas.
  - `dig_mem` and `dig_index` (Merkle DigFiles + hash-chained index).
- **Cryptography and zk circuits**
  - zkSNARK crates (`zk_snark`) including policy-eval, dig inclusion, and combined circuits.
  - Equality, high-threat, Merkle inclusion, and combined HighThreatMerkle circuits.
- **CUE tooling and schemas**
  - `utl_cue` CLI.
  - `cue/truthscript.cue`, `cue/tenant_lawbook.cue`, `cue/events.cue`.
- **Local verification tooling**
  - CLI commands to:
    - Build and inspect DigFiles.
    - Verify Merkle inclusion proofs for events.
    - Verify hash-chained dig index and policy ledger heads.
    - Export and verify `truth_snapshot` payloads.
- **Single-node or small-cluster deployments**
  - Self-hosted utld instances with local DigFiles and ledgers.
  - Optional HA features (fsync, file locks, multi-threaded utld) are kept in the core.

### 2.2 OSS Guarantees

The open core is designed so that:

- All **on-disk formats** (DigFiles, JSONL ledgers, snapshots, DecisionEvents) are documented and stable.
- Anyone can **rebuild and verify** evidence using:
  - Public CUE schemas.
  - `truthscript_semantics.md` for engine behavior.
  - The zk circuits in `zk_snark`.
- There is **no functional cripple** at the core: a motivated team can protect a real environment with the FOSS stack alone.

This maximizes adoption and makes Ritma a de-facto **standard for verifiable security evidence**, not just a product.

---

## 3. What Becomes SaaS: Ritma Cloud

Ritma Cloud is the **managed, multi-tenant control plane** and global witness layer that sits on top of the open core.

### 3.1 Key SaaS Value Propositions

1. **Managed clusters & operations**
   - Provision and scale utld clusters across regions.
   - Automatic upgrades, backups, and snapshot scheduling.
   - SLO-backed uptime and incident response.

2. **Global witness network**
   - Independent witness nodes that subscribe to:
     - Truth snapshots.
     - Dig index and policy ledger heads.
     - Selected DecisionEvent streams.
   - Witnesses **sign and replicate** hashes so that no single operator can rewrite history without collusion.

3. **External anchoring (optional)**
   - Periodically anchor snapshot hashes into:
     - Public blockchains (e.g., Bitcoin, Ethereum, others).
     - Public timestamping services.
   - Enterprises get **evidence of non-equivocation** anchored beyond their own perimeter.

4. **Enterprise control plane & UX**
   - Web console for:
     - Policy and lawbook lifecycle (review, approve, burn, roll-out).
     - Visualization of denies, threats, AI calls, entropy spikes.
     - Forensics navigation over DigFiles / policy burns / snapshots.
   - RBAC, SSO/SAML/OIDC integration.

5. **Compliance packs and guardrails**
   - Pre-built CUE + TruthScript bundles for:
     - HIPAA, GDPR, SOC2, PCI-like controls.
     - AI governance (LLM safety, PII leakage, model drift, etc.).
   - Auto-updates as regulations or best practices evolve.

6. **Integrations and ecosystem**
   - Cloud-native ingesters and exporters:
     - EDR / SIEM connectors (Splunk, Datadog, Elastic, etc.).
     - Ticketing/alerting (Jira, ServiceNow, PagerDuty, Slack, email).
     - Identity and asset sources (Okta, Azure AD, CMDBs).
   - Rich APIs for partners to embed Ritma’s truth layer.

7. **Evidence storage & governance**
   - Long-term, WORM-style DigFile and ledger storage:
     - Tiered storage for hot/warm/cold evidence.
     - Legal-hold workflows.
   - Data residency controls (per-region DigFile buckets).

### 3.2 SaaS Feature Boundaries

To keep the model honest:

- **Everything necessary to prove correctness** of local decisions and DigFiles remains in FOSS.
- SaaS adds **scale, durability, and external witnesses** that are impractical for a single org to maintain alone:
  - Geographic distribution of witnesses.
  - Anchoring to multiple external services.
  - High-availability control plane and multi-tenant UI.

---

## 4. Additional Monetizable Services from the Existing Infra

Beyond the core engine and basic Ritma Cloud, several **specialized subsystems** in the repo are natural foundations for paid services. The **crates stay free**, but Ritma Cloud can expose managed registries, analytics, and evidence vaults around them.

### 4.1 Distillium Micro-Proofs (`distillium`, `trust_container`)

- **Open core:**
  - `distillium::DistilliumMicroProof` is a signed capsule binding a `state_hash` and `parent_root` to a `zk_snip` over BLS12-381.
  - `trust_container::TrustAgreementContainer` chains these micro-proofs into agreements between parties.
- **SaaS services:**
  - **Micro-Proof Registry:** a hosted catalog of Distillium micro-proofs per tenant/root, with:
    - Search, lineage graphs, and drill-down on proof chains.
    - API to submit proofs from self-hosted utld and retrieve audit trails.
  - **Trust Agreement Service:** managed storage and visualization of `TrustAgreementContainer`s:
    - Links contracts/policies (terms_hash) to concrete micro-proof chains.
    - Suitable for vendor risk, data processing agreements, cross-tenant SLAs.
  - **Cross-org Verification Portal:** third parties (customers, regulators) can verify proofs via a hosted portal rather than running the full stack.

The **cryptographic primitives and formats remain OSS**; SaaS monetizes curation, indexing, and cross-organization verification UX.

### 4.2 Entropy & Unknown Logic Analytics (`entropy_tree`, `tracer`)

- **Open core:**
  - `entropy_tree` computes `EntropyBin`s and `EntropyHeapNode`s over DigRecords.
  - `tracer::UnknownLogicCapsule` captures inputs/outputs and descriptors for untrusted external logic.
- **SaaS services:**
  - **Entropy Analytics & Risk Scoring:**
    - Continuously compute entropy metrics over DigFiles in the cloud.
    - Surface outliers (entropy spikes, low-entropy patterns suggestive of replay or tampering).
    - Feed these into managed risk scores and alerts.
  - **Unknown Logic Registry:**
    - Central registry of `UnknownLogicCapsule`s with metadata (source repo, deploy id, owner team).
    - Queries like: "show all capsules touching service X in the last 30 days".
  - **Anomaly Detection-as-a-Service:**
    - ML models trained over entropy / capsule patterns across customers (with privacy-preserving aggregation) to flag novel attack behavior.

The **calculation and capture of entropy/capsules stays local & free**; Ritma Cloud sells advanced analytics, models, and fleet-wide baselines.

### 4.3 Forensics Store & Evidence Vault (`forensics_store`)

- **Open core:**
  - `forensics_store::persist_dig_to_fs` writes DigFiles to a local S3-style filesystem tree controlled by `UTLD_FORENSICS_DIR`.
  - Operators can run their own object stores and snapshots.
- **SaaS services:**
  - **Managed Evidence Vault:**
    - Geo-replicated, WORM-capable storage for DigFiles and ledgers.
    - Retention policies, legal holds, and export workflows.
  - **E-Discovery & Forensic Search:**
    - Indexing over DigFiles and DecisionEvents for full-text and structured search.
    - Time-travel queries over policy versions, roots, entities, capsules.
  - **Chain-of-Custody Reports:**
    - One-click export of a case bundle (DigFiles, policies, micro-proofs, snapshots) with cryptographic checksums.

The **ability to write and read DigFiles locally is never paywalled**; the cloud sells durability, indexing, and turnkey legal/compliance workflows.

### 4.4 Policy & AI Governance Packs (TruthScript + Distillium + ZK)

- **Open core:**
  - TruthScript + CUE schemas + zk circuits allow anyone to define and verify security/AI policies.
- **SaaS services:**
  - **Curated Policy Libraries:** versioned, signed libraries of:
    - Sector-specific controls (healthcare, finance, critical infra).
    - AI-specific guardrails (prompt injection, jailbreak detection, PII leakage).
  - **Policy Simulation-as-a-Service:**
    - Large-scale "what if" simulations over historical DigFiles hosted in Ritma Cloud.
    - Helps customers test new policies before go-live.
  - **Third-Party Policy Marketplace:**
    - External experts publish policies/lawbooks and share in revenue.

This turns Ritma into a **platform for security/AI governance knowledge**, while keeping the execution engine and semantics open.

---

## 5. Pricing & Monetization

### 4.1 Core Pricing Axes

A sustainable pricing model should be:

- **Aligned with value** (how much of the environment is under Ritma’s truth layer).
- **Predictable** for budgeting.
- **Technically enforceable** without heavy-handed lock-in.

Recommended primary axes:

1. **Protected scope**
   - Number of **protected entities** (hosts, services, tenants, or roots).
   - Or number of **active policy roots** / tenant-ids that feed decisions.

2. **Decision volume**
   - Number of **DecisionEvents per month** (policy evaluations).
   - Optionally capped by **unique entities** to avoid penalizing bursty workloads.

3. **Storage + retention**
   - Paid tiers include higher DigFile retention in managed storage.
   - OSS users can store their own DigFiles indefinitely; cloud retention is what’s priced.

4. **Feature tiers**
   - Advanced integrations, compliance packs, and external anchoring grouped into higher tiers.

### 4.2 Example Tiers

**Community (Free):**

- Purpose: drive adoption and experimentation.
- Includes:
  - Full FOSS stack.
  - Optional free Ritma Cloud account with:
    - Limited event volume (e.g., 100k decisions/month).
    - Short retention (e.g., 7–14 days) and 1 region.
    - Basic UI and local-only snapshots (no external anchoring).

**Team:**

- Target: small teams / startups.
- Pricing: per protected entity or per million decisions/month.
- Includes:
  - Higher volume and retention (e.g., 30–90 days).
  - Basic witness network and snapshot verification.
  - A few standard integrations (Slack, email, webhook).

**Enterprise:**

- Target: mid/large enterprises.
- Pricing: committed volume + entity count + support.
- Includes:
  - Multi-region utld clusters and witnesses.
  - Long-term evidence retention (1–7 years) with WORM options.
  - Full set of integrations and compliance packs.
  - External anchoring to chosen chains / timestamping services.
  - SSO, fine-grained RBAC, audit logs, on-call support.

**Regulated / Sovereign:**

- Target: healthcare, finance, government, defense.
- Pricing: bespoke.
- Includes:
  - Dedicated control planes or air-gapped witness networks.
  - Hardware-backed keys (HSM/KMS), FIPS modules where needed.
  - Formal attestations and independent audits.

### 4.3 How Money is Actually Earned

Revenue streams:

- **SaaS subscriptions** across the tiers (ARR, usage-based).
- **Add-ons:**
  - Extra regions / dedicated witness nodes.
  - Extra-long retention (e.g., 10+ years).
  - Custom anchoring integrations.
- **Professional services:**
  - Policy authoring and review.
  - Integrations with legacy systems.
  - Incident response / forensic analysis assistance.

Because verification is always possible via the open core, the SaaS value is in **scale, operational maturity, and external assurances**, not in monopolizing the protocol.

---

## 5. Ensuring the Core Stays Free While Still Building a Moat

Ritma’s moat should be **network and infrastructure**, not proprietary lock-in.

### 5.1 Open Formats and Specs

- All critical artifacts (DigFiles, policy ledger entries, snapshots, DecisionEvents) remain:
  - Plain JSON/JSONL with documented schemas.
  - Protected by open-source tools and zk circuits.
- `truthscript_semantics.md` and CUE schemas ensure that independent implementations can arise if needed.

This means **no one is forced** to pay Ritma Cloud to keep their historical evidence usable.

### 5.2 Network Effects in Witnessing

- The **global witness network** (with diverse operators and jurisdictions) is hard to replicate.
- Multi-party anchoring and attestation at SaaS scale becomes Ritma’s **defensible moat**:
  - Cloud service coordinates independent witnesses.
  - Enterprises benefit from shared infrastructure and audits.
  - Yet the underlying hash chain and snapshots remain verifiable by third parties.

### 5.3 Policy and Compliance Ecosystem

- CUE and TruthScript policies become a **shared language** for controls across orgs.
- Ritma Cloud can host:
  - Policy/lawbook templates.
  - Versioned, signed control sets.
  - Marketplaces for third-party auditors and vendors to publish their own guardrails.

The more parties agree on and trust these artifacts, the more Ritma becomes the **arbiter of truth** for how security decisions are made.

---

## 6. SaaS–OSS Interop Flows

### 6.1 OSS-Only Deployment

- Run `utld`, `utl_cli`, and CUE tooling on-prem.
- Use local ledgers, DigFiles, and snapshots.
- Verify all proofs and chains with the CLI and zk circuits.
- No data leaves the environment.

### 6.2 Hybrid: Self-hosted Engine + Cloud Witness

- `utld` remains self-hosted, but:
  - Periodically exports snapshots using `truth-snapshot-export`.
  - Pushes them to Ritma Cloud as a witness-only feed.
- Ritma Cloud:
  - Signs / anchors snapshots.
  - Offers dashboards and compliance reports.
- Sensitive event payloads may stay local; only **hashes and minimal metadata** leave the perimeter.

### 6.3 Full Cloud-Managed

- All `RecordTransition` traffic flows into Ritma Cloud–managed utld clusters.
- Digs and ledgers are persisted into Ritma-managed storage.
- Customers consume:
  - Dashboards and APIs for security operations.
  - Export/verify/trust guarantees via local tools when needed.

In every mode, OSS tools can **independently verify** what SaaS claims.

---

## 7. Path to Becoming the "Ultimate Truth Layer" for Cybersecurity

To become the default global truth layer:

1. **Be the best open substrate**
   - Make Ritma the easiest way to get:
     - Hash-chained, Merkle-committed logs.
     - Policy-evaluated, zk-verifiable decisions.
     - Reproducible snapshots and proofs.

2. **Standardize schemas and semantics**
   - Publish and maintain:
     - CUE schemas for policies, lawbooks, and events.
     - TruthScript semantics.
     - Dig and ledger format specs.
   - Encourage other vendors to **consume and produce** these formats.

3. **Grow the witness & anchoring network**
   - Partner with cloud providers, auditors, and regulators as independent witnesses.
   - Offer incentives for third parties to run public or private witness nodes.
   - Over time, snapshots anchored through Ritma become **cryptographic common knowledge**.

4. **Deliver enterprise-grade operations**
   - World-class SLAs, on-call support, and compliance attestations.
   - Integrate with existing workflows (SIEM, SOAR, EDR, GRC).

5. **Avoid enshittification**
   - Hard commitments:
     - Core remains open and verifiable.
     - Export and local verification are always possible.
     - SaaS value comes from **better truth**, not mere convenience.

If executed well, Ritma becomes the layer that:

- Records *what happened* in a cryptographically robust way.
- Records *why decisions were made* (policies, lawbooks, threats) in a verifiable, zk-friendly form.
- Allows anyone—from internal auditors to regulators to courts—to **verify those claims independently**, while paying Ritma to run the global infrastructure that makes such verification scalable and trustworthy by default.
