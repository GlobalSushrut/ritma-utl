# Ritma UTL Enterprise Deployment & Use Cases

## 1. Overview

The Ritma Universal Truth Layer (UTL) is a **self‑hosted security and evidence layer**. You deploy it inside your own environment (Kubernetes, VMs, bare metal) to:

- **Enforce policies** on events (e.g. HTTP requests, auth attempts, data access) using TruthScript policies.
- **Make decisions** (allow / deny / flag / seal dig window) based on enriched context and built‑in security sensors.
- **Produce verifiable evidence**: Merkle‑backed dig files, entropy bins, forensics artifacts, and structured decision logs.

UTL is designed to plug into your **existing enterprise stack**:

- API gateways / service meshes for TLS, authentication, and rate limiting.
- Identity providers (IdPs) for user and tenant identity.
- Logging / metrics / SIEM / data lake for observability and analytics.

---

## 2. Components You Deploy

### 2.1 `utld` – core daemon

- Listens on a Unix socket (`UTLD_SOCKET`).
- Holds in‑memory state:
  - State‑of‑Truth roots
  - Transition records
  - Entropy bins, capsules, micro‑proofs
- Persists to disk:
  - **Roots** → `UTLD_STATE_FILE` (default: `./utld_roots.json`).
  - **Dig files** → `UTLD_DIG_DIR`.
  - **Forensics tree** → `UTLD_FORENSICS_DIR`.
  - **Dig index JSONL** → `UTLD_DIG_INDEX`.
  - **Optional SQLite index** → `UTLD_DIG_INDEX_DB`.
  - **Decision events JSONL** → `UTLD_DECISION_EVENTS`.

### 2.2 `utl_http` – HTTP gateway

- Talks to `utld` over the Unix socket.
- Exposes HTTP endpoints:
  - `GET /health`, `GET /metrics`
  - `GET/POST /roots`
  - `POST /transitions`
  - `POST /dig`
  - `POST /entropy`
- Handles authentication and basic multi‑tenancy:
  - **Global token** via `UTLD_API_TOKEN`.
  - **Per‑tenant tokens** via `UTLD_API_TOKENS="tenantA=tokenA,tenantB=tokenB"`.
  - Enforces tenant scope using:
    - `Authorization: Bearer <token>`
    - `x-tenant-id: <tenant>` header
    - `params.tenant_id` in request body.
- Enriches events with **security signals** using pluggable tools:
  - SQL injection detection.
  - Brute‑force authentication heuristics.

---

## 3. Reference Deployment Pattern

UTL is intended to run **inside** your secure perimeter.

### 3.1 Typical Kubernetes layout

- **Pod** `utld` (two containers):
  - Container `utld`:
    - `UTLD_SOCKET=/var/run/utld/utld.sock`
    - `UTLD_POLICY=/etc/utl/policies/security_policy.json`
    - `UTLD_DIG_DIR=/var/lib/utl/dig`
    - `UTLD_FORENSICS_DIR=/var/lib/utl/forensics`
    - `UTLD_DIG_INDEX=/var/lib/utl/dig_index.jsonl`
    - `UTLD_DIG_INDEX_DB=/var/lib/utl/dig_index.sqlite`
    - `UTLD_DECISION_EVENTS=/var/lib/utl/decision_events.jsonl`
    - `UTLD_STATE_FILE=/var/lib/utl/utld_roots.json`
  - Container `utl_http`:
    - `UTLD_SOCKET=/var/run/utld/utld.sock`
    - `UTLD_HTTP_ADDR=0.0.0.0:8080`
- **Volumes**:
  - `utld-socket`: `emptyDir`, mounted at `/var/run/utld` in both containers.
  - `utld-data`: `PersistentVolumeClaim`, mounted at `/var/lib/utl` in both containers.
  - `utld-policy`: `ConfigMap` with `security_policy.json`, mounted read‑only in `utld`.
- **Service** `utl-http`:
  - ClusterIP, port 80 → forwards to `utl_http:8080`.
- **Ingress / API gateway** (your choice of controller):
  - Terminates TLS and enforces OIDC/JWT, SSO, IP allow‑lists, and rate limits.
  - Routes `/utl/*` traffic to `utl-http` Service.

### 3.2 Typical VM layout

- Single VM or pair of VMs, running `utld` + `utl_http` as systemd services.
- Shared directory for socket, e.g. `/var/run/utld/utld.sock`.
- Data directory, e.g. `/var/lib/utl` (backed up and monitored).
- Reverse proxy (Nginx/Envoy/HAProxy) in front of `utl_http` for TLS and auth.

---

## 4. Configuration for Infra Teams

### 4.1 Core connectivity

- `UTLD_SOCKET`: path to the Unix domain socket (`/var/run/utld/utld.sock`).
- `UTLD_HTTP_ADDR`: HTTP bind address for `utl_http` (`127.0.0.1:8080` by default).

### 4.2 Policy configuration

- `UTLD_POLICY`: absolute path to the TruthScript JSON policy file.
- Policies control decisions (allow / deny / seal / flag / proof) based on:
  - Event kind (`event_kind` / `event`),
  - Fields (zones, DIDs, path, severity, threat score, counters).

### 4.3 Authentication and tenants

- `UTLD_API_TOKEN`:
  - Single global bearer token for simple or single‑tenant deployments.
- `UTLD_API_TOKENS`:
  - Comma‑separated mapping: `tenantA=tokenA,tenantB=tokenB`.
  - `utl_http` enforces:
    - `Authorization: Bearer <token>` must match one of these.
    - Optional `x-tenant-id` header must equal the matched tenant.
    - For `POST /roots` and `POST /transitions`, `params.tenant_id` must equal the tenant bound to the token.

### 4.4 Integrity and cryptography

- **Transition signatures** (optional):
  - `UTLD_SIG_KEY`: hex HMAC key used by `utld` to verify transition signatures.
  - Clients compute HMAC‑SHA256 over a specific buffer (entity, root, hashes, data).
- **Dig file signatures** (optional):
  - `UTLD_DIG_SIGN_KEY`: hex HMAC key used to sign dig JSON files on disk.

### 4.5 Storage and evidence

- `UTLD_DIG_DIR`: directory for primary dig files (`*.dig.json`).
- `UTLD_FORENSICS_DIR`: S3‑style forensics tree:
  - `forensics/<tenant_id>/<YYYY>/<MM>/<DD>/root-<root>_file-<file>_<ts>.dig.json`.
- `UTLD_DIG_INDEX`: JSONL file listing dig summaries.
- `UTLD_DIG_INDEX_DB`: optional SQLite DB mirroring the index.
- `UTLD_DECISION_EVENTS`: JSONL stream of `DecisionEvent`s (policy decisions).
- `UTLD_STATE_FILE`: JSON file for persisted StateOfTruth roots.

All of these should live on **backed‑up, monitored storage**.

---

## 5. Security Posture

### 5.1 Policy‑driven controls

- TruthScript policies govern:
  - Event kinds (e.g. `http_request`, `auth_attempt`).
  - Conditions on fields and counters:
    - `field_equals`, `field_greater_than`, `count_greater_than`, `entropy_greater_than`.
- Actions include:
  - `deny` with reasons.
  - `seal_current_dig` to close and persist a window of records.
  - `flag_for_investigation` with reasons.
  - `RequireSnarkProof`, `RequireDistilliumProof`, `RequireUnknownLogicCapsule`, `CaptureInput`, `CaptureOutput`, `RecordField`.

### 5.2 Built‑in security sensors

- **SQL injection detection**:
  - Scans normalized fields and `raw_data` for patterns like `"' or 1=1"`, `"union select"`.
  - Emits labels such as `sql_injection` and raises `threat_score`.
- **Brute‑force auth detection**:
  - Evaluates `failed_attempts_last_10_min`, `success`, and metadata like `client_ip` and `actor_did`.
  - Emits labels such as `auth_bruteforce` and `auth_risk="bruteforce_suspected"`.

### 5.3 Evidence & integrity guarantees

- **Merkle‑backed dig files**:
  - Each record contributes a leaf hash based on parameters, hashes, timestamps, and content.
  - Dig files compute a Merkle root over leaves for tamper evidence.
- **Atomic file writes** for dig files and signatures.
- **Optional HMAC signatures** over dig JSON and transitions.
- **Structured decision events** written to JSONL for external consumption.

### 5.4 Process & filesystem hardening

- Unix socket permissions set to `0o660` after bind.
- Forensics directories permissions set to `0o750` on creation.

---

## 6. Customer Responsibilities

Your responsibilities when deploying UTL as a self‑hosted component:

- **Perimeter security**:
  - Place `utl_http` behind your API gateway / ingress / service mesh.
  - Terminate TLS and, if required, set up mTLS between services.
  - Apply rate limiting, WAF rules, IP allow‑lists at the gateway.

- **Identity & access management**:
  - Integrate gateway with your IdP (SSO, OIDC/JWT).
  - Map identities/claims to tenants and/or API tokens.
  - Rotate API tokens and HMAC keys using your secret management system.

- **Storage, backup, and retention**:
  - Choose and provision storage for dig files, forensics, indexes, logs, and roots.
  - Apply backup, retention, and archival policies consistent with your compliance requirements.

- **Observability & incident response**:
  - Scrape `/metrics` into your metrics stack.
  - Ingest JSONL logs (decision events, dig index) into SIEM / data lake.
  - Use dig files and decision logs as part of incident investigations and audits.

UTL provides the **policy, enforcement, and evidence engine**; you provide the **runtime environment and governance envelope**.

---

## 7. How This Is Useful to AI Systems

Modern AI systems – especially LLMs and autonomous agents – introduce new governance and safety requirements. UTL is particularly valuable as an **AI control and evidence layer**:

1. **Guardrails around AI APIs**
   - Place UTL in front of model inference and embedding APIs.
   - Use TruthScript policies to:
     - Deny or flag requests with sensitive content (e.g. PII, regulated terms) based on sensors and metadata.
     - Apply rate limits and per‑tenant quotas (e.g. number of model calls).

2. **Auditability of AI decisions**
   - Record every AI call as a `record_transition` with parameters:
     - `tenant_id`, `model_name`, `model_version`, `prompt_hash`, `risk_score`, etc.
   - Persist Merkle‑backed dig files and decision events:
     - Enables after‑the‑fact reconstruction of how a particular output or decision was made.
     - Supports regulatory and internal audit requirements for AI governance.

3. **Policy‑driven AI safety**
   - Encode safety rules in TruthScript:
     - Example: deny certain event kinds if `threat_score` from upstream classifiers > threshold.
     - Example: require additional approvals or proofs (e.g. `RequireSnarkProof` or `RequireDistilliumProof`) for high‑risk AI actions.
   - Integrate signals from AI‑specific detectors (prompt injection, jailbreak, toxicity) as additional fields and conditions.

4. **Enterprise AI observability**
   - Dig files and decision logs give a structured, tamper‑evident history of AI interactions.
   - Entropy bins and counters can be used as coarse signals of:
     - Novelty or anomalous use.
     - Bursty or unexpected patterns that may indicate abuse or misconfiguration.

5. **Multi‑tenant AI platforms**
   - For platforms hosting AI services for many customers, UTL’s tenant‑scoped tokens and policies help:
     - Enforce tenant boundaries on sensitive AI actions.
     - Provide each tenant with evidence artifacts (dig files, decision logs) proving how their traffic was handled.

In short, UTL acts as a **universal guardrail and evidence recorder** around AI workloads:

- Policies encode **what is allowed**.
- Digs and logs show **what actually happened**.
- Cryptographic hashing/signatures provide **integrity** and **non‑repudiation**.

This combination is powerful for AI safety, regulatory compliance (e.g. EU AI Act‑style obligations), and internal risk management.

---

## 8. Example Enterprise Use Cases by Domain

Below are 30 example domains where UTL can be deployed as a self‑hosted component.

1. **Healthcare (EHR / EMR)**  
   Enforce policies on patient record queries (e.g. excessive patient searches, cross‑tenant access), log every sensitive access into dig files for HIPAA audits.

2. **Health insurance (claims)**  
   Record transitions through multi‑step claims pipelines, detect anomalous claim patterns (e.g. high‑risk providers) and seal evidence for fraud investigations.

3. **Retail banking (core + APIs)**  
   Monitor account transfers and API calls, deny high‑risk flows (unapproved geo/zone hops) and produce signed evidence for internal audit and regulators.

4. **Payments / PSPs**  
   Attach UTL to checkout, card authorization, and payout flows; block SQLi and brute‑force auth against merchant dashboards, preserve tamper‑evident logs for chargeback disputes.

5. **Wealth management / brokerage**  
   Enforce policies around high‑risk trading events (large orders, privileged accounts) and preserve evidence trails for MiFID II/SEC compliance.

6. **Retail / e‑commerce**  
   Use UTL on customer profile and order APIs to detect abuse (credential stuffing, anomalous searches), seal dig windows during suspected fraud waves.

7. **Telecommunications (subscriber APIs)**  
   Govern access to subscriber data and location APIs; block cross‑zone data exfiltration and keep entropy bins for anomaly analytics.

8. **Media & streaming**  
   Monitor entitlements and playback/session APIs, capture evidence for content rights enforcement and detect suspicious concurrent use patterns.

9. **Social networks / community platforms**  
   Apply policies on moderation tools and user data access, log every high‑risk admin action in signed dig files for later investigations.

10. **Public sector / government services**  
    Deploy inside government data centers to log citizen record access, deny unauthorized cross‑agency flows, and furnish independent, Merkle‑backed audit artifacts.

11. **Defense / intelligence**  
    Put UTL as a guard around cross‑domain gateways (e.g. secret ↔ top secret), enforce per‑zone rules and preserve evidence for cross‑domain movement approvals.

12. **Critical infrastructure / energy**  
    Instrument SCADA/OT control APIs with policies restricting dangerous commands, capture event sequences into dig files for incident forensics.

13. **Manufacturing / industrial IoT**  
    Wrap device configuration and firmware update endpoints; detect unusual change patterns and seal dig windows for safety investigations.

14. **Logistics & supply chain**  
    Govern shipment status updates, customs events, and inventory APIs; detect suspicious event bursts (e.g. mass cancel) and preserve evidence.

15. **Airlines & travel**  
    Enforce controls on PNR (booking) and passenger data APIs; block abusive search patterns, zone‑restricted access, and log all high‑risk touches.

16. **Hospitality (hotels, OTAs)**  
    Secure guest profile and reservation systems; detect brute‑force login attempts, risky modifications, and produce signed logs for disputes.

17. **EdTech / universities**  
    Control access to student records and grade APIs, detect excessive access (e.g. mass grade downloads) and preserve evidence for FERPA‑style audits.

18. **HR / people systems**  
    Enforce policies on employee record access, block unapproved geo/tenant flows, and create evidence for internal HR/legal investigations.

19. **Legal tech / document management**  
    Track access and modifications to legal documents, seal dig files when a case crosses certain thresholds (e.g. external sharing), providing chain‑of‑custody.

20. **Real estate / PropTech**  
    Govern deal‑room/document access and financial data sharing in property transactions; record all sensitive transitions for later dispute resolution.

21. **FinOps / ERP**  
    Capture journal entries, approvals, and changes to high‑risk financial objects; enforce rules for unusual patterns (e.g. high entropy of changes) and keep signed logs for auditors.

22. **Data warehouse / analytics platforms**  
    Front SQL/BI APIs with UTL policies that limit access to sensitive datasets, detect abuse (broad table dumps) and produce independent dig files for access audits.

23. **Data lake / data mesh**  
    Enforce per‑zone and per‑tenant policies on data product access; compute entropy bins to detect out‑of‑pattern usage and keep cryptographically‑linked evidence.

24. **ML / AI platforms (model serving)**  
    Guard inference endpoints; implement rate limits and content guardrails (e.g. PII access, prompt injection patterns), log all high‑risk calls and policy decisions for AI governance.

25. **Security products (e.g. EDR/XDR vendors)**  
    Embed UTL as a policy and evidence layer over detection and response events, helping customers prove what actions were taken, when, and under which policy.

26. **Identity & access management platforms**  
    Apply policies to sensitive IAM operations (role changes, SSO connections), detect brute‑force and anomalous admin activity, and preserve evidence for zero‑trust reviews.

27. **Crypto / Web3 exchanges**  
    Monitor fiat/crypto movement calls, enforce policy around KYC/AML flags, and produce immutable dig files for regulators and external auditors.

28. **RegTech / compliance solutions**  
    Use UTL as an embedded omniscient log of regulated events (e.g. insider trading controls, communications surveillance), feeding external compliance tools.

29. **AdTech / marketing platforms**  
    Enforce consent and policy on audience/segment usage, capture every high‑risk activation event into dig files for privacy compliance (GDPR/CCPA).

30. **Cross‑border data transfer gateways**  
    Put UTL at jurisdictional boundaries; enforce zone‑based policies (`src_zone`, `dst_zone`), deny unapproved flows, and maintain evidence of all allowed/denied transfers.
