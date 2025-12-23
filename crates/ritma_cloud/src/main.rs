use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use dig_index::DigIndexQuery;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tokio::sync::RwLock;

// Canonical feature keys for paid Ritma products. These strings are used in
// OrgPlan.features to gate functionality in UIs and services.
const FEATURE_RITMA_CLOUD: &str = "ritma_cloud";
const FEATURE_COMPLIANCE_PDF_PACKS: &str = "compliance_pdf_packs";
const FEATURE_POLICY_STUDIO_PRO: &str = "policy_studio_pro";
const FEATURE_FORENSICS_VAULT: &str = "forensics_vault";
const FEATURE_WITNESS_NETWORK: &str = "witness_network";
const FEATURE_AI_GUARDRAIL_PACKS: &str = "ai_guardrail_packs";
const FEATURE_AUDITOR_PORTAL: &str = "auditor_portal";
const FEATURE_RITMA_SHIELD: &str = "ritma_shield";
const FEATURE_COMPLIANCE_PACKS: &str = "compliance_packs";
const FEATURE_EVENT_REPLAY_ENGINE: &str = "event_replay_engine";
const FEATURE_SECRETS_KMS: &str = "secrets_kms";
const FEATURE_SECURE_INFERENCE_RUNTIME: &str = "secure_inference_runtime";
const FEATURE_INTEGRATIONS_PACK: &str = "integrations_pack";
const FEATURE_ENTERPRISE_SUPPORT: &str = "enterprise_support";
const FEATURE_APPLIANCE: &str = "appliance";
// Optional / future extensions
const FEATURE_LOG_INGEST_SAAS: &str = "log_ingest_saas";
const FEATURE_ZK_PROOF_SERVICE: &str = "zk_proof_service";
const FEATURE_TRUTHSCRIPT_MARKETPLACE: &str = "truthscript_marketplace";
const FEATURE_CLUSTER_INSURANCE: &str = "cluster_insurance";
const FEATURE_INDUSTRY_BLUEPRINTS: &str = "industry_blueprints";

#[derive(Clone, Default)]
struct AppState {
    inner: Arc<RwLock<InMemoryState>>,
    db: Option<PgPool>,
}

/// Simple in-memory storage. This is intentionally structured so that it can be
/// swapped for a PostgreSQL-backed implementation later without changing the
/// external API. Two logical pipelines are modeled:
/// - secrets: key summaries with hashed identifiers
/// - index: evidence summaries and SLO summaries
#[derive(Default)]
struct InMemoryState {
    orgs: Vec<Org>,
    tenants: Vec<Tenant>,
    nodes: Vec<NodeWallet>,
    evidence: Vec<EvidenceSummary>,
    reports: Vec<ReportSummary>,
    report_artifacts: Vec<ReportArtifact>,
    rulepacks: Vec<ComplianceRulepack>,
    org_rulepacks: Vec<OrgRulepackBinding>,
    keys: Vec<KeySummary>,
    slos: Vec<SloSummary>,
    org_plans: Vec<OrgPlan>,
    replay_jobs: Vec<ReplayJob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Org {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Tenant {
    id: String,
    org_id: String,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeWallet {
    id: String,
    org_id: String,
    label: Option<String>,
    region: Option<String>,
    capabilities: Vec<String>,
    last_heartbeat_at: Option<u64>,
}

fn normalize_node_id(raw: &str) -> String {
    let trimmed = raw.trim().to_lowercase();
    if trimmed.starts_with("node:") {
        trimmed
    } else {
        format!("node:{trimmed}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvidenceSummary {
    package_id: String,
    org_id: String,
    tenant_id: String,
    node_id: String,
    scope: String,
    report_type: Option<String>,
    framework: Option<String>,
    signed: bool,
    created_at: u64,
}

#[derive(Debug, Deserialize)]
struct ReportCreateRequest {
    org_id: String,
    tenant_id: Option<String>,
    scope: String,
    framework: Option<String>,
}

/// Cloud-side summary of a generated compliance report tied to evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReportSummary {
    id: String,
    org_id: String,
    tenant_id: Option<String>,
    scope: String,
    framework: Option<String>,
    /// Evidence packages that contributed to this report.
    evidence_ids: Vec<String>,
    created_at: u64,
}

/// Stub representation of a generated PDF + cryptographic proof bundle for a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReportArtifact {
    id: String,
    report_id: String,
    org_id: String,
    kind: String,
    created_at: u64,
    note: String,
}

/// Simple per-org plan & feature flags. This is the core of "payment mode" and
/// can later be backed by a proper billing system.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrgPlan {
    org_id: String,
    /// Human-readable plan name, e.g. "starter", "enterprise", "gov".
    plan: String,
    /// Enabled products/features for this org, e.g. ["ritma_cloud", "forensics_vault"].
    features: Vec<String>,
}

/// Catalog entry for a compliance rulepack (e.g. SOC2, PCI DSS, ISO27001).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComplianceRulepack {
    id: String,
    name: String,
    description: String,
    framework: Option<String>,
    version: Option<String>,
}

/// Binding of a rulepack to an org (optionally scoped to a tenant).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrgRulepackBinding {
    org_id: String,
    tenant_id: Option<String>,
    rulepack_id: String,
}

/// Digest of an evidence summary for proof bundles.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvidenceDigest {
    package_id: String,
    sha256: String,
}

/// Proof bundle tying a report manifest and evidence to stable hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReportProofBundle {
    report_id: String,
    org_id: String,
    generated_at: u64,
    manifest_sha256: String,
    evidence_digests: Vec<EvidenceDigest>,
}

#[derive(Debug, Deserialize)]
struct RegisterKeyRequest {
    org_id: String,
    node_id: String,
    key_id: String,
    key_hash: String,
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SloIngestRequest {
    org_id: String,
    tenant_id: Option<String>,
    node_id: String,
    component: String,
    operation: String,
    outcome: String,
    count: u64,
    window_start: u64,
    window_end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplayJob {
    id: String,
    org_id: String,
    tenant_id: Option<String>,
    time_start: u64,
    time_end: u64,
    status: String,
    created_at: u64,
    note: Option<String>,
    /// Optional policy decision filter for this replay (e.g. "deny").
    policy_decision: Option<String>,
    /// Human-readable summary of what the replay found.
    result_summary: Option<String>,
    /// Completion timestamp for the replay job.
    completed_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct PolicyDecisionCount {
    policy_decision: String,
    count: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ReplaySourceStats {
    total: u64,
    by_policy_decision: Vec<PolicyDecisionCount>,
    by_tenant: Vec<TenantCount>,
    by_policy_name: Vec<PolicyNameCount>,
    sample_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayJobResult {
    job: ReplayJob,
    dig_index_total: u64,
    decision_events_total: u64,
    dig_index_by_policy_decision: Vec<PolicyDecisionCount>,
    decision_events_by_policy_decision: Vec<PolicyDecisionCount>,
    dig_index_by_tenant: Vec<TenantCount>,
    decision_events_by_tenant: Vec<TenantCount>,
    dig_index_by_policy_name: Vec<PolicyNameCount>,
    decision_events_by_policy_name: Vec<PolicyNameCount>,
    dig_index_sample_ids: Vec<String>,
    decision_events_sample_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct TenantCount {
    tenant_id: String,
    count: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PolicyNameCount {
    policy_name: String,
    count: u64,
}

/// Secret pipeline summary: describes a key without exposing the secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeySummary {
    /// Stable key identifier (node-local keystore ID).
    key_id: String,
    /// Hash of the key material or public half, computed by the node.
    key_hash: String,
    org_id: String,
    node_id: String,
    /// Optional description / usage hints.
    label: Option<String>,
    /// Governance status for this key (e.g. active, revoked, compromised, deprecated).
    status: String,
    /// First time this key_id was seen in the cloud control plane.
    created_at: Option<u64>,
    /// Last time governance metadata was updated.
    updated_at: Option<u64>,
    /// Last time a node reported this key via telemetry.
    last_seen_at: Option<u64>,
    /// Optional successor key for rotation.
    replaced_by_key_id: Option<String>,
    /// Optional freeform governance note.
    governance_note: Option<String>,
}

/// Index pipeline summary for SLOs: aggregated view per component/operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SloSummary {
    org_id: String,
    tenant_id: Option<String>,
    node_id: String,
    component: String,
    operation: String,
    outcome: String,
    /// Aggregated count over a time window.
    count: u64,
    window_start: u64,
    window_end: u64,
}

#[derive(Debug, Deserialize)]
struct RegisterNodeRequest {
    org_id: String,
    node_id: String,
    label: Option<String>,
    region: Option<String>,
    capabilities: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct EvidenceIngestRequest {
    org_id: String,
    tenant_id: String,
    node_id: String,
    package_id: String,
    scope: String,
    report_type: Option<String>,
    framework: Option<String>,
    signed: bool,
    created_at: u64,
}

#[derive(Debug, Serialize)]
struct OverviewResponse {
    org_id: String,
    org_name: String,
    tenant_count: usize,
    node_count: usize,
    evidence_count: usize,
}

#[derive(Debug, Serialize)]
struct SloOverviewResponse {
    org_id: String,
    tenant_id: Option<String>,
    component: String,
    operation: String,
    outcome: String,
    total_count: u64,
}

/// Simple usage summary per org for billing/metering.
#[derive(Debug, Serialize)]
struct UsageSummary {
    org_id: String,
    org_name: String,
    tenants: u64,
    nodes: u64,
    evidence: u64,
    slo_events: u64,
}

/// Summary of key governance state for a given org.
#[derive(Debug, Serialize)]
struct OrgKeySummaryResponse {
    org_id: String,
    total_keys: u64,
    by_status: HashMap<String, u64>,
}

#[derive(Debug, Deserialize)]
struct OrgCreateRequest {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct TenantCreateRequest {
    id: String,
    org_id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct NodeListQuery {
    org_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NodeHeartbeatRequest {
    org_id: String,
}

#[derive(Debug, Deserialize)]
struct AuditorEvidenceQuery {
    tenant_id: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuditorReportsQuery {
    tenant_id: Option<String>,
    framework: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReplayJobCreateRequest {
    org_id: String,
    tenant_id: Option<String>,
    time_start: u64,
    time_end: u64,
    note: Option<String>,
    policy_decision: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReplayJobListQuery {
    org_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DecisionEventLite {
    ts: u64,
    tenant_id: Option<String>,
    policy_decision: String,
    policy_name: Option<String>,
    record_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReplayResultsQuery {
    /// Optional source selector: "dig_index", "decision_events", or omitted for both.
    source: Option<String>,
    /// Optional filter to focus on a single policy decision in the breakdowns.
    policy_decision: Option<String>,
    /// Optional filter to focus on a single tenant in the breakdowns.
    tenant_id: Option<String>,
    /// Optional filter to focus on a single policy name in the breakdowns.
    policy_name: Option<String>,
    /// Pagination for sampled IDs (dig_index_sample_ids / decision_events_sample_ids).
    sample_offset: Option<usize>,
    sample_limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct OrgPlanSetRequest {
    org_id: String,
    plan: String,
    features: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RulepackCreateRequest {
    id: String,
    name: String,
    description: Option<String>,
    framework: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RulepackToggleRequest {
    rulepack_id: String,
    tenant_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct OrgFeaturesResponse {
    org_id: String,
    plan: Option<String>,
    ritma_cloud: bool,
    compliance_pdf_packs: bool,
    policy_studio_pro: bool,
    forensics_vault: bool,
    witness_network: bool,
    ai_guardrail_packs: bool,
    auditor_portal: bool,
    ritma_shield: bool,
    compliance_packs: bool,
    event_replay_engine: bool,
    secrets_kms: bool,
    secure_inference_runtime: bool,
    integrations_pack: bool,
    enterprise_support: bool,
    appliance: bool,
    log_ingest_saas: bool,
    zk_proof_service: bool,
    truthscript_marketplace: bool,
    cluster_insurance: bool,
    industry_blueprints: bool,
}

async fn health() -> &'static str {
    "ok"
}

async fn list_orgs(State(state): State<AppState>) -> Json<Vec<Org>> {
    let inner = state.inner.read().await;
    Json(inner.orgs.clone())
}

async fn list_tenants(State(state): State<AppState>) -> Json<Vec<Tenant>> {
    let inner = state.inner.read().await;
    Json(inner.tenants.clone())
}

async fn list_org_plans(State(state): State<AppState>) -> Json<Vec<OrgPlan>> {
    let inner = state.inner.read().await;
    Json(inner.org_plans.clone())
}

async fn create_org(State(state): State<AppState>, Json(req): Json<OrgCreateRequest>) -> Json<Org> {
    let org = {
        let mut inner = state.inner.write().await;
        let org = Org {
            id: req.id,
            name: req.name,
        };
        inner.orgs.push(org.clone());
        org
    };

    if let Some(ref pool) = state.db {
        let _ = sqlx::query("INSERT INTO orgs (id, name) VALUES ($1, $2)\n                     ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name")
            .bind(&org.id)
            .bind(&org.name)
            .execute(pool)
            .await;
    }
    Json(org)
}

async fn create_tenant(
    State(state): State<AppState>,
    Json(req): Json<TenantCreateRequest>,
) -> Json<Tenant> {
    let tenant = {
        let mut inner = state.inner.write().await;
        let tenant = Tenant {
            id: req.id,
            org_id: req.org_id,
            name: req.name,
        };
        inner.tenants.push(tenant.clone());
        tenant
    };

    if let Some(ref pool) = state.db {
        let _ = sqlx::query("INSERT INTO tenants (id, org_id, name) VALUES ($1, $2, $3)\n                     ON CONFLICT (id) DO UPDATE SET org_id = EXCLUDED.org_id, name = EXCLUDED.name")
            .bind(&tenant.id)
            .bind(&tenant.org_id)
            .bind(&tenant.name)
            .execute(pool)
            .await;
    }

    Json(tenant)
}

async fn set_org_plan(
    State(state): State<AppState>,
    Json(req): Json<OrgPlanSetRequest>,
) -> Json<OrgPlan> {
    let features = req.features.unwrap_or_else(Vec::new);
    let new_plan = OrgPlan {
        org_id: req.org_id,
        plan: req.plan,
        features,
    };

    let out_plan = {
        let mut inner = state.inner.write().await;

        // Replace existing plan for this org if present, otherwise insert new.
        if let Some(existing) = inner
            .org_plans
            .iter_mut()
            .find(|p| p.org_id == new_plan.org_id)
        {
            *existing = new_plan.clone();
            existing.clone()
        } else {
            inner.org_plans.push(new_plan.clone());
            new_plan.clone()
        }
    };

    if let Some(ref pool) = state.db {
        let features_str = out_plan.features.join(",");
        let _ = sqlx::query("INSERT INTO org_plans (org_id, plan, features) VALUES ($1, $2, $3)\n                     ON CONFLICT (org_id) DO UPDATE SET plan = EXCLUDED.plan, features = EXCLUDED.features")
            .bind(&out_plan.org_id)
            .bind(&out_plan.plan)
            .bind(&features_str)
            .execute(pool)
            .await;
    }

    Json(out_plan)
}

async fn get_org_features(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Json<OrgFeaturesResponse> {
    let inner = state.inner.read().await;

    let plan_opt = inner.org_plans.iter().find(|p| p.org_id == org_id);
    let has = |feature: &str| inner.org_has_feature(&org_id, feature);

    let resp = OrgFeaturesResponse {
        org_id: org_id.clone(),
        plan: plan_opt.map(|p| p.plan.clone()),
        ritma_cloud: has(FEATURE_RITMA_CLOUD),
        compliance_pdf_packs: has(FEATURE_COMPLIANCE_PDF_PACKS),
        policy_studio_pro: has(FEATURE_POLICY_STUDIO_PRO),
        forensics_vault: has(FEATURE_FORENSICS_VAULT),
        witness_network: has(FEATURE_WITNESS_NETWORK),
        ai_guardrail_packs: has(FEATURE_AI_GUARDRAIL_PACKS),
        auditor_portal: has(FEATURE_AUDITOR_PORTAL),
        ritma_shield: has(FEATURE_RITMA_SHIELD),
        compliance_packs: has(FEATURE_COMPLIANCE_PACKS),
        event_replay_engine: has(FEATURE_EVENT_REPLAY_ENGINE),
        secrets_kms: has(FEATURE_SECRETS_KMS),
        secure_inference_runtime: has(FEATURE_SECURE_INFERENCE_RUNTIME),
        integrations_pack: has(FEATURE_INTEGRATIONS_PACK),
        enterprise_support: has(FEATURE_ENTERPRISE_SUPPORT),
        appliance: has(FEATURE_APPLIANCE),
        log_ingest_saas: has(FEATURE_LOG_INGEST_SAAS),
        zk_proof_service: has(FEATURE_ZK_PROOF_SERVICE),
        truthscript_marketplace: has(FEATURE_TRUTHSCRIPT_MARKETPLACE),
        cluster_insurance: has(FEATURE_CLUSTER_INSURANCE),
        industry_blueprints: has(FEATURE_INDUSTRY_BLUEPRINTS),
    };

    Json(resp)
}

async fn list_nodes(
    State(state): State<AppState>,
    Query(q): Query<NodeListQuery>,
) -> Json<Vec<NodeWallet>> {
    let inner = state.inner.read().await;
    let nodes: Vec<NodeWallet> = match q.org_id {
        Some(org) => inner
            .nodes
            .iter()
            .filter(|n| n.org_id == org)
            .cloned()
            .collect(),
        None => inner.nodes.clone(),
    };
    Json(nodes)
}

async fn register_node(
    State(state): State<AppState>,
    Json(req): Json<RegisterNodeRequest>,
) -> Json<NodeWallet> {
    let node = {
        let mut inner = state.inner.write().await;
        let node = NodeWallet {
            id: normalize_node_id(&req.node_id),
            org_id: req.org_id,
            label: req.label,
            region: req.region,
            capabilities: req.capabilities.unwrap_or_default(),
            last_heartbeat_at: None,
        };
        inner.nodes.push(node.clone());
        node
    };

    if let Some(ref pool) = state.db {
        let _ = sqlx::query("INSERT INTO nodes (id, org_id) VALUES ($1, $2)\n                     ON CONFLICT (id) DO UPDATE SET org_id = EXCLUDED.org_id")
            .bind(&node.id)
            .bind(&node.org_id)
            .execute(pool)
            .await;
    }

    Json(node)
}

async fn node_heartbeat(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(req): Json<NodeHeartbeatRequest>,
) -> Result<Json<NodeWallet>, StatusCode> {
    let mut inner = state.inner.write().await;
    let normalized = normalize_node_id(&node_id);

    if let Some(node) = inner
        .nodes
        .iter_mut()
        .find(|n| n.id == normalized && n.org_id == req.org_id)
    {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        node.last_heartbeat_at = Some(now);
        return Ok(Json(node.clone()));
    }

    Err(StatusCode::NOT_FOUND)
}

async fn create_replay_job(
    State(state): State<AppState>,
    Json(req): Json<ReplayJobCreateRequest>,
) -> Json<ReplayJob> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let id = format!("rj-{now}");

    let job = {
        let mut inner = state.inner.write().await;
        let job = ReplayJob {
            id,
            org_id: req.org_id,
            tenant_id: req.tenant_id,
            time_start: req.time_start,
            time_end: req.time_end,
            status: "pending".to_string(),
            created_at: now,
            note: req.note,
            policy_decision: req.policy_decision,
            result_summary: None,
            completed_at: None,
        };
        inner.replay_jobs.push(job.clone());
        job
    };

    if let Some(ref pool) = state.db {
        let _ = sqlx::query(
            "INSERT INTO replay_jobs (id, org_id, tenant_id, time_start, time_end, status, created_at, note, policy_decision, result_summary, completed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&job.id)
        .bind(&job.org_id)
        .bind(&job.tenant_id)
        .bind(job.time_start as i64)
        .bind(job.time_end as i64)
        .bind(&job.status)
        .bind(job.created_at as i64)
        .bind(&job.note)
        .bind(&job.policy_decision)
        .bind(&job.result_summary)
        .bind(job.completed_at.map(|v| v as i64))
        .execute(pool)
        .await;
    }

    // Kick off the replay asynchronously; clients can poll /replay_jobs to observe status.
    let state_for_task = state.clone();
    let job_id_for_task = job.id.clone();
    tokio::spawn(async move {
        run_replay_job_worker(state_for_task, job_id_for_task).await;
    });

    Json(job)
}

async fn list_replay_jobs(
    State(state): State<AppState>,
    Query(query): Query<ReplayJobListQuery>,
) -> Json<Vec<ReplayJob>> {
    let inner = state.inner.read().await;
    let mut jobs = inner.replay_jobs.clone();
    if let Some(org) = query.org_id {
        jobs.retain(|j| j.org_id == org);
    }
    Json(jobs)
}

async fn get_replay_job_results(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Query(q): Query<ReplayResultsQuery>,
) -> Result<Json<ReplayJobResult>, StatusCode> {
    let job_opt = {
        let inner = state.inner.read().await;
        inner.replay_jobs.iter().find(|j| j.id == job_id).cloned()
    };

    let job = match job_opt {
        Some(j) => j,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let (dig_stats_opt, decision_stats_opt) =
        tokio::join!(run_dig_index_replay(&job), run_decision_log_replay(&job),);

    let dig_raw = dig_stats_opt.unwrap_or(ReplaySourceStats {
        total: 0,
        by_policy_decision: Vec::new(),
        by_tenant: Vec::new(),
        by_policy_name: Vec::new(),
        sample_ids: Vec::new(),
    });
    let dec_raw = decision_stats_opt.unwrap_or(ReplaySourceStats {
        total: 0,
        by_policy_decision: Vec::new(),
        by_tenant: Vec::new(),
        by_policy_name: Vec::new(),
        sample_ids: Vec::new(),
    });

    // Helper to apply axis filters and sample pagination to a ReplaySourceStats.
    fn filter_stats(stats: &ReplaySourceStats, q: &ReplayResultsQuery) -> ReplaySourceStats {
        let mut by_policy_decision = stats.by_policy_decision.clone();
        let mut by_tenant = stats.by_tenant.clone();
        let mut by_policy_name = stats.by_policy_name.clone();
        let mut sample_ids = stats.sample_ids.clone();

        if let Some(ref decision) = q.policy_decision {
            by_policy_decision.retain(|c| &c.policy_decision == decision);
        }
        if let Some(ref tenant) = q.tenant_id {
            by_tenant.retain(|c| &c.tenant_id == tenant);
        }
        if let Some(ref name) = q.policy_name {
            by_policy_name.retain(|c| &c.policy_name == name);
        }

        // Apply simple offset/limit pagination over the sampled IDs.
        let offset = q.sample_offset.unwrap_or(0);
        let limit = q.sample_limit.unwrap_or(sample_ids.len());
        if offset < sample_ids.len() {
            let end = (offset + limit).min(sample_ids.len());
            sample_ids = sample_ids[offset..end].to_vec();
        } else {
            sample_ids.clear();
        }

        ReplaySourceStats {
            total: stats.total,
            by_policy_decision,
            by_tenant,
            by_policy_name,
            sample_ids,
        }
    }

    let source = q.source.as_deref();
    let include_dig = !matches!(source, Some("decision_events"));
    let include_dec = !matches!(source, Some("dig_index"));

    let dig_stats = if include_dig {
        filter_stats(&dig_raw, &q)
    } else {
        ReplaySourceStats {
            total: 0,
            by_policy_decision: Vec::new(),
            by_tenant: Vec::new(),
            by_policy_name: Vec::new(),
            sample_ids: Vec::new(),
        }
    };

    let decision_stats = if include_dec {
        filter_stats(&dec_raw, &q)
    } else {
        ReplaySourceStats {
            total: 0,
            by_policy_decision: Vec::new(),
            by_tenant: Vec::new(),
            by_policy_name: Vec::new(),
            sample_ids: Vec::new(),
        }
    };

    let result = ReplayJobResult {
        job,
        dig_index_total: dig_stats.total,
        decision_events_total: decision_stats.total,
        dig_index_by_policy_decision: dig_stats.by_policy_decision.clone(),
        decision_events_by_policy_decision: decision_stats.by_policy_decision.clone(),
        dig_index_by_tenant: dig_stats.by_tenant.clone(),
        decision_events_by_tenant: decision_stats.by_tenant.clone(),
        dig_index_by_policy_name: dig_stats.by_policy_name.clone(),
        decision_events_by_policy_name: decision_stats.by_policy_name.clone(),
        dig_index_sample_ids: dig_stats.sample_ids.clone(),
        decision_events_sample_ids: decision_stats.sample_ids.clone(),
    };

    Ok(Json(result))
}

async fn run_replay_job_worker(state: AppState, job_id: String) {
    let job_spec = {
        let mut inner = state.inner.write().await;
        let job_opt = inner.replay_jobs.iter_mut().find(|j| j.id == job_id);
        let job = match job_opt {
            Some(j) => {
                j.status = "running".to_string();
                j.clone()
            }
            None => return,
        };

        if let Some(ref pool) = state.db {
            let _ = sqlx::query("UPDATE replay_jobs SET status = $1 WHERE id = $2")
                .bind(&job.status)
                .bind(&job.id)
                .execute(pool)
                .await;
        }

        job
    };

    let dig_stats = run_dig_index_replay(&job_spec).await;
    let decision_stats = run_decision_log_replay(&job_spec).await;

    let dig_total = dig_stats.as_ref().map(|s| s.total).unwrap_or(0);
    let decision_total = decision_stats.as_ref().map(|s| s.total).unwrap_or(0);

    let dig_policy_json = dig_stats
        .as_ref()
        .and_then(|s| serde_json::to_string(&s.by_policy_decision).ok())
        .unwrap_or_else(|| "[]".to_string());
    let decision_policy_json = decision_stats
        .as_ref()
        .and_then(|s| serde_json::to_string(&s.by_policy_decision).ok())
        .unwrap_or_else(|| "[]".to_string());

    let completed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let summary = format!(
        "dig_index_total={dig_total} decision_events_total={decision_total} dig_index_by_policy={dig_policy_json} decision_events_by_policy={decision_policy_json}"
    );

    {
        let mut inner = state.inner.write().await;
        if let Some(j) = inner.replay_jobs.iter_mut().find(|j| j.id == job_id) {
            j.status = "completed".to_string();
            j.completed_at = Some(completed_at);
            j.result_summary = Some(summary.clone());
        }
    }

    if let Some(ref pool) = state.db {
        let _ = sqlx::query(
            "UPDATE replay_jobs SET status = $1, completed_at = $2, result_summary = $3 WHERE id = $4",
        )
        .bind("completed")
        .bind(completed_at as i64)
        .bind(&summary)
        .bind(&job_id)
        .execute(pool)
        .await;
    }
}

async fn run_dig_index_replay(job: &ReplayJob) -> Option<ReplaySourceStats> {
    let db_path = match std::env::var("RITMA_REPLAY_DIG_INDEX_DB")
        .or_else(|_| std::env::var("UTLD_DIG_INDEX_DB"))
    {
        Ok(p) => p,
        Err(_) => return None,
    };

    let job_clone = job.clone();
    tokio::task::spawn_blocking(move || {
        let mut query = DigIndexQuery::new().time_range(job_clone.time_start, job_clone.time_end);
        if let Some(ref tenant) = job_clone.tenant_id {
            query = query.tenant(tenant.clone());
        }
        if let Some(ref decision) = job_clone.policy_decision {
            query = query.decision(decision.clone());
        }

        match query.execute(&db_path) {
            Ok(entries) => {
                let total = entries.len() as u64;
                let mut policy_map: HashMap<String, u64> = HashMap::new();
                let mut tenant_map: HashMap<String, u64> = HashMap::new();
                let mut name_map: HashMap<String, u64> = HashMap::new();
                let mut sample_ids: Vec<String> = Vec::new();

                for e in entries {
                    let policy_key = e
                        .policy_decision
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string());
                    *policy_map.entry(policy_key).or_insert(0) += 1;

                    let tenant_key = e.tenant_id.clone().unwrap_or_else(|| "unknown".to_string());
                    *tenant_map.entry(tenant_key).or_insert(0) += 1;

                    let name_key = e
                        .policy_name
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string());
                    *name_map.entry(name_key).or_insert(0) += 1;

                    if sample_ids.len() < 50 {
                        sample_ids.push(e.file_id.clone());
                    }
                }

                let mut by_policy_decision: Vec<PolicyDecisionCount> = policy_map
                    .into_iter()
                    .map(|(policy_decision, count)| PolicyDecisionCount {
                        policy_decision,
                        count,
                    })
                    .collect();
                by_policy_decision.sort_by(|a, b| a.policy_decision.cmp(&b.policy_decision));

                let mut by_tenant: Vec<TenantCount> = tenant_map
                    .into_iter()
                    .map(|(tenant_id, count)| TenantCount { tenant_id, count })
                    .collect();
                by_tenant.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));

                let mut by_policy_name: Vec<PolicyNameCount> = name_map
                    .into_iter()
                    .map(|(policy_name, count)| PolicyNameCount { policy_name, count })
                    .collect();
                by_policy_name.sort_by(|a, b| a.policy_name.cmp(&b.policy_name));

                Some(ReplaySourceStats {
                    total,
                    by_policy_decision,
                    by_tenant,
                    by_policy_name,
                    sample_ids,
                })
            }
            Err(e) => {
                eprintln!("replay dig_index query failed: {e}");
                None
            }
        }
    })
    .await
    .ok()
    .flatten()
}

async fn run_decision_log_replay(job: &ReplayJob) -> Option<ReplaySourceStats> {
    let path = std::env::var("RITMA_REPLAY_DECISION_LOG")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());

    let job_clone = job.clone();
    tokio::task::spawn_blocking(move || {
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(_) => return None,
        };
        let reader = BufReader::new(file);
        let mut total: u64 = 0;
        let mut policy_map: HashMap<String, u64> = HashMap::new();
        let mut tenant_map: HashMap<String, u64> = HashMap::new();
        let mut name_map: HashMap<String, u64> = HashMap::new();
        let mut sample_ids: Vec<String> = Vec::new();

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            if line.trim().is_empty() {
                continue;
            }

            let ev: DecisionEventLite = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue,
            };

            if ev.ts < job_clone.time_start || ev.ts > job_clone.time_end {
                continue;
            }

            if let Some(ref tenant) = job_clone.tenant_id {
                if ev.tenant_id.as_deref() != Some(tenant.as_str()) {
                    continue;
                }
            }

            if let Some(ref decision) = job_clone.policy_decision {
                if ev.policy_decision != *decision {
                    continue;
                }
            }

            total += 1;

            *policy_map.entry(ev.policy_decision.clone()).or_insert(0) += 1;

            let tenant_key = ev
                .tenant_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            *tenant_map.entry(tenant_key).or_insert(0) += 1;

            let name_key = ev
                .policy_name
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            *name_map.entry(name_key).or_insert(0) += 1;

            if sample_ids.len() < 50 {
                if let Some(h) = ev.record_hash.clone() {
                    sample_ids.push(h);
                }
            }
        }

        let mut by_policy_decision: Vec<PolicyDecisionCount> = policy_map
            .into_iter()
            .map(|(policy_decision, count)| PolicyDecisionCount {
                policy_decision,
                count,
            })
            .collect();
        by_policy_decision.sort_by(|a, b| a.policy_decision.cmp(&b.policy_decision));

        let mut by_tenant: Vec<TenantCount> = tenant_map
            .into_iter()
            .map(|(tenant_id, count)| TenantCount { tenant_id, count })
            .collect();
        by_tenant.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));

        let mut by_policy_name: Vec<PolicyNameCount> = name_map
            .into_iter()
            .map(|(policy_name, count)| PolicyNameCount { policy_name, count })
            .collect();
        by_policy_name.sort_by(|a, b| a.policy_name.cmp(&b.policy_name));

        Some(ReplaySourceStats {
            total,
            by_policy_decision,
            by_tenant,
            by_policy_name,
            sample_ids,
        })
    })
    .await
    .ok()
    .flatten()
}

async fn ingest_evidence(
    State(state): State<AppState>,
    Json(req): Json<EvidenceIngestRequest>,
) -> Json<EvidenceSummary> {
    let ev = {
        let mut inner = state.inner.write().await;
        let ev = EvidenceSummary {
            package_id: req.package_id,
            org_id: req.org_id,
            tenant_id: req.tenant_id,
            node_id: normalize_node_id(&req.node_id),
            scope: req.scope,
            report_type: req.report_type,
            framework: req.framework,
            signed: req.signed,
            created_at: req.created_at,
        };
        inner.evidence.push(ev.clone());
        ev
    };

    if let Some(ref pool) = state.db {
        let _ = sqlx::query(
            "INSERT INTO evidence (package_id, org_id, tenant_id, node_id, scope, report_type, framework, signed, created_at)\n             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)\n             ON CONFLICT (package_id) DO UPDATE SET\n                 org_id=$2, tenant_id=$3, node_id=$4, scope=$5, report_type=$6, framework=$7, signed=$8, created_at=$9",
        )
        .bind(&ev.package_id)
        .bind(&ev.org_id)
        .bind(&ev.tenant_id)
        .bind(&ev.node_id)
        .bind(&ev.scope)
        .bind(&ev.report_type)
        .bind(&ev.framework)
        .bind(ev.signed)
        .bind(ev.created_at as i64)
        .execute(pool)
        .await;
    }

    Json(ev)
}

async fn list_evidence(State(state): State<AppState>) -> Json<Vec<EvidenceSummary>> {
    let inner = state.inner.read().await;
    Json(inner.evidence.clone())
}

async fn list_reports(State(state): State<AppState>) -> Json<Vec<ReportSummary>> {
    let inner = state.inner.read().await;
    Json(inner.reports.clone())
}

async fn auditor_list_evidence(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Query(q): Query<AuditorEvidenceQuery>,
) -> Json<Vec<EvidenceSummary>> {
    let inner = state.inner.read().await;

    let mut out: Vec<EvidenceSummary> = inner
        .evidence
        .iter()
        .filter(|e| e.org_id == org_id)
        .cloned()
        .collect();

    if let Some(ref tenant_id) = q.tenant_id {
        out.retain(|e| &e.tenant_id == tenant_id);
    }
    if let Some(ref scope) = q.scope {
        out.retain(|e| &e.scope == scope);
    }

    Json(out)
}

async fn auditor_list_reports(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Query(q): Query<AuditorReportsQuery>,
) -> Json<Vec<ReportSummary>> {
    let inner = state.inner.read().await;

    let mut out: Vec<ReportSummary> = inner
        .reports
        .iter()
        .filter(|r| r.org_id == org_id)
        .cloned()
        .collect();

    if let Some(ref tenant_id) = q.tenant_id {
        out.retain(|r| r.tenant_id.as_ref() == Some(tenant_id));
    }
    if let Some(ref framework) = q.framework {
        out.retain(|r| r.framework.as_ref() == Some(framework));
    }

    Json(out)
}

#[derive(Debug, Serialize)]
struct AuditorRoleDefinition {
    name: String,
    description: String,
}

async fn list_auditor_roles() -> Json<Vec<AuditorRoleDefinition>> {
    Json(vec![
        AuditorRoleDefinition {
            name: "auditor".to_string(),
            description:
                "Org-scoped read-only access to evidence, reports, and manifests for compliance review."
                    .to_string(),
        },
        AuditorRoleDefinition {
            name: "regulator".to_string(),
            description:
                "Read-only access plus long-term archive and bundle retrieval for regulatory oversight."
                    .to_string(),
        },
    ])
}

#[derive(Debug, Serialize)]
struct ReportManifest {
    report: ReportSummary,
    evidence: Vec<EvidenceSummary>,
}

async fn get_report_manifest(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> Result<Json<ReportManifest>, StatusCode> {
    let inner = state.inner.read().await;

    let report = match inner.reports.iter().find(|r| r.id == report_id) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let evidence: Vec<EvidenceSummary> = inner
        .evidence
        .iter()
        .filter(|e| e.org_id == report.org_id)
        .filter(|e| report.evidence_ids.iter().any(|id| id == &e.package_id))
        .cloned()
        .collect();

    let manifest = ReportManifest {
        report: report.clone(),
        evidence,
    };

    Ok(Json(manifest))
}

async fn get_report_proof(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> Result<Json<ReportProofBundle>, StatusCode> {
    let inner = state.inner.read().await;

    let report = match inner.reports.iter().find(|r| r.id == report_id) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Reuse the same logic as get_report_manifest to collect evidence.
    let evidence: Vec<EvidenceSummary> = inner
        .evidence
        .iter()
        .filter(|e| e.org_id == report.org_id)
        .filter(|e| report.evidence_ids.iter().any(|id| id == &e.package_id))
        .cloned()
        .collect();

    let manifest = ReportManifest {
        report: report.clone(),
        evidence: evidence.clone(),
    };

    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let manifest_sha = Sha256::digest(&manifest_bytes);
    let manifest_sha_hex = hex::encode(manifest_sha);

    let mut evidence_digests = Vec::new();
    for ev in evidence {
        let bytes = serde_json::to_vec(&ev).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let hash = Sha256::digest(&bytes);
        evidence_digests.push(EvidenceDigest {
            package_id: ev.package_id,
            sha256: hex::encode(hash),
        });
    }

    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let bundle = ReportProofBundle {
        report_id: report.id.clone(),
        org_id: report.org_id.clone(),
        generated_at,
        manifest_sha256: manifest_sha_hex,
        evidence_digests,
    };

    Ok(Json(bundle))
}

async fn generate_report_bundle(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> Result<Json<ReportArtifact>, StatusCode> {
    let mut inner = state.inner.write().await;

    let report = match inner.reports.iter().find(|r| r.id == report_id) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let id = format!("rpt-art-{}", inner.report_artifacts.len() + 1);

    let artifact = ReportArtifact {
        id,
        report_id: report.id.clone(),
        org_id: report.org_id.clone(),
        kind: "pdf+proof_stub".to_string(),
        created_at,
        note: "Stub artifact. In a full implementation this would store a PDF and cryptographic proof bundle.".to_string(),
    };

    inner.report_artifacts.push(artifact.clone());

    Ok(Json(artifact))
}

async fn create_report(
    State(state): State<AppState>,
    Json(req): Json<ReportCreateRequest>,
) -> Json<ReportSummary> {
    let mut inner = state.inner.write().await;

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let id = format!("rpt-{}", inner.reports.len() + 1);

    let evidence_ids = inner
        .evidence
        .iter()
        .filter(|e| e.org_id == req.org_id)
        .filter(|e| req.tenant_id.as_ref().is_none_or(|t| &e.tenant_id == t))
        .filter(|e| e.scope == req.scope)
        .map(|e| e.package_id.clone())
        .collect();

    let report = ReportSummary {
        id,
        org_id: req.org_id,
        tenant_id: req.tenant_id,
        scope: req.scope,
        framework: req.framework,
        evidence_ids,
        created_at,
    };

    inner.reports.push(report.clone());
    Json(report)
}

async fn register_key(
    State(state): State<AppState>,
    Json(req): Json<RegisterKeyRequest>,
) -> Json<KeySummary> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let key = {
        let mut inner = state.inner.write().await;

        // If the key already exists in memory, update mutable fields and bump timestamps.
        if let Some(existing) = inner.keys.iter_mut().find(|k| k.key_id == req.key_id) {
            existing.key_hash = req.key_hash;
            existing.org_id = req.org_id;
            existing.node_id = normalize_node_id(&req.node_id);
            existing.label = req.label;
            existing.last_seen_at = Some(now);
            existing.updated_at = Some(now);
            existing.clone()
        } else {
            let key = KeySummary {
                key_id: req.key_id,
                key_hash: req.key_hash,
                org_id: req.org_id,
                node_id: normalize_node_id(&req.node_id),
                label: req.label,
                status: "active".to_string(),
                created_at: Some(now),
                updated_at: Some(now),
                last_seen_at: Some(now),
                replaced_by_key_id: None,
                governance_note: None,
            };
            inner.keys.push(key.clone());
            key
        }
    };

    if let Some(ref pool) = state.db {
        let _ = sqlx::query(
            "INSERT INTO keys (key_id, key_hash, org_id, node_id, label, status, created_at, updated_at, last_seen_at, replaced_by_key_id, governance_note)\n             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)\n             ON CONFLICT (key_id) DO UPDATE SET key_hash=$2, org_id=$3, node_id=$4, label=$5, status=$6, updated_at=$8, last_seen_at=$9, replaced_by_key_id=$10, governance_note=$11",
        )
        .bind(&key.key_id)
        .bind(&key.key_hash)
        .bind(&key.org_id)
        .bind(&key.node_id)
        .bind(&key.label)
        .bind(&key.status)
        .bind(key.created_at.map(|v| v as i64))
        .bind(key.updated_at.map(|v| v as i64))
        .bind(key.last_seen_at.map(|v| v as i64))
        .bind(&key.replaced_by_key_id)
        .bind(&key.governance_note)
        .execute(pool)
        .await;
    }

    Json(key)
}

#[derive(Debug, Deserialize)]
struct KeysQuery {
    org_id: Option<String>,
    status: Option<String>,
    node_id: Option<String>,
}

async fn list_keys(
    State(state): State<AppState>,
    Query(query): Query<KeysQuery>,
) -> Json<Vec<KeySummary>> {
    let inner = state.inner.read().await;
    let mut keys: Vec<KeySummary> = inner.keys.clone();

    if let Some(ref org_id) = query.org_id {
        keys.retain(|k| &k.org_id == org_id);
    }

    if let Some(ref status) = query.status {
        keys.retain(|k| &k.status == status);
    }

    if let Some(ref node_id) = query.node_id {
        let normalized = normalize_node_id(node_id);
        keys.retain(|k| k.node_id == normalized);
    }

    Json(keys)
}

async fn get_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<KeySummary>, StatusCode> {
    let inner = state.inner.read().await;
    match inner.keys.iter().find(|k| k.key_id == key_id) {
        Some(k) => Ok(Json(k.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_org_key_summary(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Json<OrgKeySummaryResponse> {
    let inner = state.inner.read().await;

    let mut by_status: HashMap<String, u64> = HashMap::new();
    let mut total = 0u64;

    for key in inner.keys.iter().filter(|k| k.org_id == org_id) {
        total += 1;
        *by_status.entry(key.status.clone()).or_insert(0) += 1;
    }

    Json(OrgKeySummaryResponse {
        org_id,
        total_keys: total,
        by_status,
    })
}

#[derive(Debug, Deserialize)]
struct KeyGovernanceUpdate {
    status: Option<String>,
    replaced_by_key_id: Option<String>,
    governance_note: Option<String>,
}

async fn update_key_governance(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Json(req): Json<KeyGovernanceUpdate>,
) -> Result<Json<KeySummary>, StatusCode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut inner = state.inner.write().await;
    let key = match inner.keys.iter_mut().find(|k| k.key_id == key_id) {
        Some(k) => k,
        None => return Err(StatusCode::NOT_FOUND),
    };

    if let Some(status) = req.status {
        key.status = status;
    }
    if let Some(replaced) = req.replaced_by_key_id {
        key.replaced_by_key_id = Some(replaced);
    }
    if let Some(note) = req.governance_note {
        key.governance_note = Some(note);
    }
    key.updated_at = Some(now);

    let key_clone = key.clone();

    drop(inner);

    if let Some(ref pool) = state.db {
        let _ = sqlx::query(
            "UPDATE keys SET status=$2, replaced_by_key_id=$3, governance_note=$4, updated_at=$5 WHERE key_id=$1",
        )
        .bind(&key_id)
        .bind(&key_clone.status)
        .bind(&key_clone.replaced_by_key_id)
        .bind(&key_clone.governance_note)
        .bind(key_clone.updated_at.map(|v| v as i64))
        .execute(pool)
        .await;
    }

    Ok(Json(key_clone))
}

async fn ingest_slo(
    State(state): State<AppState>,
    Json(req): Json<SloIngestRequest>,
) -> Json<SloSummary> {
    let slo = {
        let mut inner = state.inner.write().await;
        let slo = SloSummary {
            org_id: req.org_id,
            tenant_id: req.tenant_id,
            node_id: normalize_node_id(&req.node_id),
            component: req.component,
            operation: req.operation,
            outcome: req.outcome,
            count: req.count,
            window_start: req.window_start,
            window_end: req.window_end,
        };
        inner.slos.push(slo.clone());
        slo
    };

    if let Some(ref pool) = state.db {
        let _ = sqlx::query(
            "INSERT INTO slos (org_id, tenant_id, node_id, component, operation, outcome, count, window_start, window_end)\n             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(&slo.org_id)
        .bind(&slo.tenant_id)
        .bind(&slo.node_id)
        .bind(&slo.component)
        .bind(&slo.operation)
        .bind(&slo.outcome)
        .bind(slo.count as i64)
        .bind(slo.window_start as i64)
        .bind(slo.window_end as i64)
        .execute(pool)
        .await;
    }

    Json(slo)
}

async fn list_rulepacks(State(state): State<AppState>) -> Json<Vec<ComplianceRulepack>> {
    let inner = state.inner.read().await;
    Json(inner.rulepacks.clone())
}

async fn create_rulepack(
    State(state): State<AppState>,
    Json(req): Json<RulepackCreateRequest>,
) -> Json<ComplianceRulepack> {
    let mut inner = state.inner.write().await;

    let rp = ComplianceRulepack {
        id: req.id,
        name: req.name,
        description: req
            .description
            .unwrap_or_else(|| "Custom compliance rulepack".to_string()),
        framework: req.framework,
        version: req.version,
    };

    inner.rulepacks.push(rp.clone());
    Json(rp)
}

async fn list_org_rulepacks(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Query(q): Query<AuditorEvidenceQuery>,
) -> Json<Vec<ComplianceRulepack>> {
    let inner = state.inner.read().await;

    let tenant_filter = q.tenant_id;

    let mut out = Vec::new();
    for binding in inner.org_rulepacks.iter().filter(|b| b.org_id == org_id) {
        if tenant_filter.is_some() && binding.tenant_id != tenant_filter {
            continue;
        }
        if let Some(rp) = inner.rulepacks.iter().find(|r| r.id == binding.rulepack_id) {
            out.push(rp.clone());
        }
    }

    Json(out)
}

async fn enable_org_rulepack(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<RulepackToggleRequest>,
) -> Json<OrgRulepackBinding> {
    let mut inner = state.inner.write().await;

    let binding = OrgRulepackBinding {
        org_id: org_id.clone(),
        tenant_id: req.tenant_id,
        rulepack_id: req.rulepack_id,
    };

    // Avoid duplicate bindings.
    if !inner.org_rulepacks.iter().any(|b| {
        b.org_id == binding.org_id
            && b.tenant_id == binding.tenant_id
            && b.rulepack_id == binding.rulepack_id
    }) {
        inner.org_rulepacks.push(binding.clone());
    }

    Json(binding)
}

async fn disable_org_rulepack(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<RulepackToggleRequest>,
) -> Json<()> {
    let mut inner = state.inner.write().await;

    inner.org_rulepacks.retain(|b| {
        !(b.org_id == org_id && b.rulepack_id == req.rulepack_id && b.tenant_id == req.tenant_id)
    });

    Json(())
}

async fn list_slo_summary(State(state): State<AppState>) -> Json<Vec<SloOverviewResponse>> {
    let inner = state.inner.read().await;

    let mut out: Vec<SloOverviewResponse> = Vec::new();

    for slo in &inner.slos {
        // Simple aggregation by (org, tenant, component, operation, outcome).
        if let Some(existing) = out.iter_mut().find(|s| {
            s.org_id == slo.org_id
                && s.tenant_id == slo.tenant_id
                && s.component == slo.component
                && s.operation == slo.operation
                && s.outcome == slo.outcome
        }) {
            existing.total_count += slo.count;
        } else {
            out.push(SloOverviewResponse {
                org_id: slo.org_id.clone(),
                tenant_id: slo.tenant_id.clone(),
                component: slo.component.clone(),
                operation: slo.operation.clone(),
                outcome: slo.outcome.clone(),
                total_count: slo.count,
            });
        }
    }

    Json(out)
}

async fn org_usage(State(state): State<AppState>) -> Json<Vec<UsageSummary>> {
    let inner = state.inner.read().await;

    let mut out = Vec::new();
    for org in &inner.orgs {
        let tenants = inner.tenants.iter().filter(|t| t.org_id == org.id).count() as u64;
        let nodes = inner.nodes.iter().filter(|n| n.org_id == org.id).count() as u64;
        let evidence = inner.evidence.iter().filter(|e| e.org_id == org.id).count() as u64;
        let slo_events: u64 = inner
            .slos
            .iter()
            .filter(|s| s.org_id == org.id)
            .map(|s| s.count)
            .sum();

        out.push(UsageSummary {
            org_id: org.id.clone(),
            org_name: org.name.clone(),
            tenants,
            nodes,
            evidence,
            slo_events,
        });
    }

    Json(out)
}

async fn org_overview(State(state): State<AppState>) -> Json<Vec<OverviewResponse>> {
    let inner = state.inner.read().await;

    let mut out = Vec::new();
    for org in &inner.orgs {
        let tenant_count = inner.tenants.iter().filter(|t| t.org_id == org.id).count();
        let node_count = inner.nodes.iter().filter(|n| n.org_id == org.id).count();
        let evidence_count = inner.evidence.iter().filter(|e| e.org_id == org.id).count();

        out.push(OverviewResponse {
            org_id: org.id.clone(),
            org_name: org.name.clone(),
            tenant_count,
            node_count,
            evidence_count,
        });
    }

    Json(out)
}

impl InMemoryState {
    /// Check whether an org has a specific feature enabled in its plan.
    fn org_has_feature(&self, org_id: &str, feature: &str) -> bool {
        self.org_plans
            .iter()
            .find(|p| p.org_id == org_id)
            .map(|p| p.features.iter().any(|f| f == feature))
            .unwrap_or(false)
    }
}

async fn init_pg_pool_from_env() -> Option<PgPool> {
    let dsn = match std::env::var("RITMA_PG_DSN") {
        Ok(v) if !v.is_empty() => v,
        _ => return None,
    };

    match PgPool::connect(&dsn).await {
        Ok(pool) => {
            if let Err(e) = run_migrations(&pool).await {
                eprintln!("ritma_cloud: failed to run PostgreSQL migrations: {e}");
            }
            Some(pool)
        }
        Err(e) => {
            eprintln!("ritma_cloud: failed to connect to PostgreSQL ({e}), running in-memory only");
            None
        }
    }
}

async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    // Minimal schema for core control-plane entities. These are intentionally simple
    // and can be evolved later with proper migration tooling.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS orgs (\n             id   TEXT PRIMARY KEY,\n             name TEXT NOT NULL\n         )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS replay_jobs (\n             id         TEXT PRIMARY KEY,\n             org_id     TEXT NOT NULL,\n             tenant_id  TEXT,\n             time_start BIGINT NOT NULL,\n             time_end   BIGINT NOT NULL,\n             status     TEXT NOT NULL,\n             created_at BIGINT NOT NULL,\n             note       TEXT\n         )",
    )
    .execute(pool)
    .await?;

    sqlx::query("ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS policy_decision TEXT")
        .execute(pool)
        .await?;

    sqlx::query("ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS result_summary TEXT")
        .execute(pool)
        .await?;

    sqlx::query("ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS completed_at BIGINT")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenants (\n             id     TEXT PRIMARY KEY,\n             org_id TEXT NOT NULL,\n             name   TEXT NOT NULL\n         )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS nodes (\n             id     TEXT PRIMARY KEY,\n             org_id TEXT NOT NULL\n         )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS evidence (\n             package_id TEXT PRIMARY KEY,\n             org_id     TEXT NOT NULL,\n             tenant_id  TEXT NOT NULL,\n             node_id    TEXT NOT NULL,\n             scope      TEXT NOT NULL,\n             report_type TEXT,\n             framework   TEXT,\n             signed      BOOLEAN NOT NULL,\n             created_at  BIGINT NOT NULL\n         )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS keys (\n             key_id   TEXT PRIMARY KEY,\n             key_hash TEXT NOT NULL,\n             org_id   TEXT NOT NULL,\n             node_id  TEXT NOT NULL,\n             label    TEXT,\n             status   TEXT NOT NULL,\n             created_at BIGINT,\n             updated_at BIGINT,\n             last_seen_at BIGINT,\n             replaced_by_key_id TEXT,\n             governance_note TEXT\n         )",
    )
    .execute(pool)
    .await?;

    sqlx::query("ALTER TABLE keys ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'")
        .execute(pool)
        .await?;

    sqlx::query("ALTER TABLE keys ADD COLUMN IF NOT EXISTS created_at BIGINT")
        .execute(pool)
        .await?;

    sqlx::query("ALTER TABLE keys ADD COLUMN IF NOT EXISTS updated_at BIGINT")
        .execute(pool)
        .await?;

    sqlx::query("ALTER TABLE keys ADD COLUMN IF NOT EXISTS last_seen_at BIGINT")
        .execute(pool)
        .await?;

    sqlx::query("ALTER TABLE keys ADD COLUMN IF NOT EXISTS replaced_by_key_id TEXT")
        .execute(pool)
        .await?;

    sqlx::query("ALTER TABLE keys ADD COLUMN IF NOT EXISTS governance_note TEXT")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS slos (\n             org_id       TEXT NOT NULL,\n             tenant_id    TEXT,\n             node_id      TEXT NOT NULL,\n             component    TEXT NOT NULL,\n             operation    TEXT NOT NULL,\n             outcome      TEXT NOT NULL,\n             count        BIGINT NOT NULL,\n             window_start BIGINT NOT NULL,\n             window_end   BIGINT NOT NULL\n         )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS org_plans (\n             org_id   TEXT PRIMARY KEY,\n             plan     TEXT NOT NULL,\n             features TEXT NOT NULL\n         )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn hydrate_state_from_db(pool: &PgPool, inner: Arc<RwLock<InMemoryState>>) {
    if let Ok(rows) = sqlx::query("SELECT id, name FROM orgs")
        .fetch_all(pool)
        .await
    {
        let orgs = rows
            .into_iter()
            .map(|row| Org {
                id: row.get("id"),
                name: row.get("name"),
            })
            .collect();

        let mut state = inner.write().await;
        state.orgs = orgs;
    }

    if let Ok(rows) = sqlx::query("SELECT id, org_id, name FROM tenants")
        .fetch_all(pool)
        .await
    {
        let tenants = rows
            .into_iter()
            .map(|row| Tenant {
                id: row.get("id"),
                org_id: row.get("org_id"),
                name: row.get("name"),
            })
            .collect();

        let mut state = inner.write().await;
        state.tenants = tenants;
    }

    if let Ok(rows) = sqlx::query("SELECT id, org_id FROM nodes")
        .fetch_all(pool)
        .await
    {
        let nodes = rows
            .into_iter()
            .map(|row| NodeWallet {
                id: row.get("id"),
                org_id: row.get("org_id"),
                label: None,
                region: None,
                capabilities: Vec::new(),
                last_heartbeat_at: None,
            })
            .collect();

        let mut state = inner.write().await;
        state.nodes = nodes;
    }

    if let Ok(rows) = sqlx::query(
        "SELECT package_id, org_id, tenant_id, node_id, scope, report_type, framework, signed, created_at FROM evidence",
    )
    .fetch_all(pool)
    .await
    {
        let evidence = rows
            .into_iter()
            .map(|row| {
                let created_at: i64 = row.get("created_at");
                EvidenceSummary {
                    package_id: row.get("package_id"),
                    org_id: row.get("org_id"),
                    tenant_id: row.get("tenant_id"),
                    node_id: row.get("node_id"),
                    scope: row.get("scope"),
                    report_type: row.get("report_type"),
                    framework: row.get("framework"),
                    signed: row.get("signed"),
                    created_at: created_at as u64,
                }
            })
            .collect();

        let mut state = inner.write().await;
        state.evidence = evidence;
    }

    if let Ok(rows) = sqlx::query(
        "SELECT key_id, key_hash, org_id, node_id, label, status, created_at, updated_at, last_seen_at, replaced_by_key_id, governance_note FROM keys",
    )
        .fetch_all(pool)
        .await
    {
        let keys = rows
            .into_iter()
            .map(|row| KeySummary {
                key_id: row.get("key_id"),
                key_hash: row.get("key_hash"),
                org_id: row.get("org_id"),
                node_id: row.get("node_id"),
                label: row.get("label"),
                status: row.get("status"),
                created_at: {
                    let v: Option<i64> = row.get("created_at");
                    v.map(|x| x as u64)
                },
                updated_at: {
                    let v: Option<i64> = row.get("updated_at");
                    v.map(|x| x as u64)
                },
                last_seen_at: {
                    let v: Option<i64> = row.get("last_seen_at");
                    v.map(|x| x as u64)
                },
                replaced_by_key_id: row.get("replaced_by_key_id"),
                governance_note: row.get("governance_note"),
            })
            .collect();

        let mut state = inner.write().await;
        state.keys = keys;
    }

    if let Ok(rows) = sqlx::query(
        "SELECT org_id, tenant_id, node_id, component, operation, outcome, count, window_start, window_end FROM slos",
    )
    .fetch_all(pool)
    .await
    {
        let slos = rows
            .into_iter()
            .map(|row| {
                let count: i64 = row.get("count");
                let window_start: i64 = row.get("window_start");
                let window_end: i64 = row.get("window_end");
                SloSummary {
                    org_id: row.get("org_id"),
                    tenant_id: row.get("tenant_id"),
                    node_id: row.get("node_id"),
                    component: row.get("component"),
                    operation: row.get("operation"),
                    outcome: row.get("outcome"),
                    count: count as u64,
                    window_start: window_start as u64,
                    window_end: window_end as u64,
                }
            })
            .collect();

        let mut state = inner.write().await;
        state.slos = slos;
    }

    if let Ok(rows) = sqlx::query("SELECT org_id, plan, features FROM org_plans")
        .fetch_all(pool)
        .await
    {
        let plans = rows
            .into_iter()
            .map(|row| {
                let features_str: String = row.get("features");
                let features = if features_str.is_empty() {
                    Vec::new()
                } else {
                    features_str.split(',').map(|s| s.to_string()).collect()
                };

                OrgPlan {
                    org_id: row.get("org_id"),
                    plan: row.get("plan"),
                    features,
                }
            })
            .collect();

        let mut state = inner.write().await;
        state.org_plans = plans;
    }

    if let Ok(rows) = sqlx::query("SELECT id, org_id, tenant_id, time_start, time_end, status, created_at, note, policy_decision, result_summary, completed_at FROM replay_jobs")
        .fetch_all(pool)
        .await
    {
        let jobs = rows
            .into_iter()
            .map(|row| {
                let time_start: i64 = row.get("time_start");
                let time_end: i64 = row.get("time_end");
                let created_at: i64 = row.get("created_at");
                let completed_at: Option<i64> = row.get("completed_at");
                ReplayJob {
                    id: row.get("id"),
                    org_id: row.get("org_id"),
                    tenant_id: row.get("tenant_id"),
                    time_start: time_start as u64,
                    time_end: time_end as u64,
                    status: row.get("status"),
                    created_at: created_at as u64,
                    note: row.get("note"),
                    policy_decision: row.get("policy_decision"),
                    result_summary: row.get("result_summary"),
                    completed_at: completed_at.map(|v| v as u64),
                }
            })
            .collect();

        let mut state = inner.write().await;
        state.replay_jobs = jobs;
    }
}

async fn require_api_key(
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // If no API key is configured, run in open/dev mode.
    let expected = match std::env::var("RITMA_CLOUD_API_KEY") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(next.run(req).await),
    };

    let provided = req
        .headers()
        .get("x-ritma-api-key")
        .and_then(|v| v.to_str().ok());

    if provided != Some(expected.as_str()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Optional org scoping: if a caller supplies X-Ritma-Org-Id, ensure it matches
    // any org id embedded in the URL path (/orgs/:org_id/...).
    if let Some(header_org) = req
        .headers()
        .get("x-ritma-org-id")
        .and_then(|v| v.to_str().ok())
    {
        let path = req.uri().path();
        let segments: Vec<&str> = path.split('/').collect();
        if let Some(pos) = segments.iter().position(|s| *s == "orgs") {
            if let Some(path_org) = segments.get(pos + 1) {
                if header_org != *path_org {
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        }
    }

    Ok(next.run(req).await)
}

#[tokio::main]
async fn main() {
    let db = init_pg_pool_from_env().await;

    let state = AppState {
        inner: Arc::new(RwLock::new(InMemoryState::default())),
        db,
    };

    if let Some(ref pool) = state.db {
        hydrate_state_from_db(pool, state.inner.clone()).await;
    }

    let protected_routes = Router::new()
        .route("/orgs", get(list_orgs).post(create_org))
        .route("/tenants", get(list_tenants).post(create_tenant))
        .route("/org_plans", get(list_org_plans).post(set_org_plan))
        .route("/orgs/:org_id/features", get(get_org_features))
        .route("/rulepacks", get(list_rulepacks).post(create_rulepack))
        .route("/orgs/:org_id/rulepacks", get(list_org_rulepacks))
        .route("/orgs/:org_id/rulepacks/enable", post(enable_org_rulepack))
        .route(
            "/orgs/:org_id/rulepacks/disable",
            post(disable_org_rulepack),
        )
        .route("/nodes", get(list_nodes))
        .route("/nodes/register", post(register_node))
        .route("/nodes/:node_id/heartbeat", post(node_heartbeat))
        .route("/evidence", post(ingest_evidence).get(list_evidence))
        .route("/reports", get(list_reports).post(create_report))
        .route("/reports/:report_id/manifest", get(get_report_manifest))
        .route("/reports/:report_id/proof", get(get_report_proof))
        .route("/reports/:report_id/bundle", post(generate_report_bundle))
        .route("/auditor/orgs/:org_id/evidence", get(auditor_list_evidence))
        .route("/auditor/orgs/:org_id/reports", get(auditor_list_reports))
        .route("/auditor/roles", get(list_auditor_roles))
        // Secret pipeline: key summaries (hashed ids only, no secrets).
        .route("/keys", post(register_key).get(list_keys))
        .route("/keys/:key_id", get(get_key).patch(update_key_governance))
        .route("/orgs/:org_id/keys/summary", get(get_org_key_summary))
        // Index pipeline: SLO summaries across components/tenants/nodes.
        .route("/slo/ingest", post(ingest_slo))
        .route("/slo/summary", get(list_slo_summary))
        .route("/overview", get(org_overview))
        .route("/usage", get(org_usage))
        .route(
            "/replay_jobs",
            get(list_replay_jobs).post(create_replay_job),
        )
        .route("/replay_jobs/:id/results", get(get_replay_job_results))
        .route_layer(middleware::from_fn(require_api_key));

    let app = Router::new()
        .route("/health", get(health))
        .merge(protected_routes)
        .with_state(state);

    let addr: SocketAddr = std::env::var("RITMA_CLOUD_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8088".to_string())
        .parse()
        .expect("invalid RITMA_CLOUD_ADDR");

    println!("ritma_cloud listening on {addr}");

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}
