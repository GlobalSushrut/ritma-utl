use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;

use axum::{
    async_trait,
    extract::{FromRequestParts, Path, Query, State},
    http::{request::Parts, StatusCode},
    routing::{get, post},
    Json, Router,
};
use compliance_index::{BurnConfig, BurnProcess, ComplianceBurn, ControlEvalRecord};
use compliance_model::{Control, load_controls_from_file};
use compliance_rulepacks::{Rulepack, RulepackMetadata, soc2_rulepack, hipaa_rulepack, ai_safety_controls};
use core_types::UID;
use dig_index::{DigIndexEntry, DigIndexQuery};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use serde::{Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct OrgSummary {
    org_id: String,
    name: String,
}

#[derive(Serialize)]
struct MeResponse {
    user_id: String,
    orgs: Vec<OrgSummary>,
    roles: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    burn_dir: String,
}

#[derive(Clone, Debug)]
struct AuthContext {
    user_id: String,
    org_id: Option<String>,
    roles: Vec<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let headers = &parts.headers;

        let user_id = headers
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("demo-user")
            .to_string();

        let org_id = headers
            .get("x-org-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let roles: Vec<String> = headers
            .get("x-roles")
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                s.split(',')
                    .map(|r| r.trim().to_string())
                    .filter(|r| !r.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| vec!["org_owner".to_string()]);

        Ok(AuthContext {
            user_id,
            org_id,
            roles,
        })
    }
}

#[derive(Deserialize)]
struct BurnsQuery {
    tenant_id: String,
    framework: String,
}

#[derive(Deserialize)]
struct PartialBurnsQuery {
    tenant_id: Option<String>,
    framework: Option<String>,
}

#[derive(Serialize)]
struct BurnMetadata {
    burn_id: String,
    timestamp: u64,
    tenant_id: String,
    framework: String,
    merkle_root: String,
    record_count: usize,
    prev_burn_hash: Option<String>,
    burn_hash: String,
    total_controls: usize,
    passed_controls: usize,
    failed_controls: usize,
    pass_rate: f64,
}

#[derive(Deserialize)]
struct EvidenceSearchQuery {
    tenant_id: Option<String>,
    framework: Option<String>,
    burn_id: Option<String>,
    policy_decision: Option<String>,
    time_start: Option<u64>,
    time_end: Option<u64>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct EvidenceSearchResult {
    entry: DigIndexEntry,
}

#[derive(Deserialize)]
struct SloEventsQuery {
    tenant_id: Option<String>,
    component: Option<String>,
    operation: Option<String>,
    outcome: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SloEventRecord {
    ts: u64,
    component: String,
    operation: String,
    tenant_id: Option<String>,
    target: Option<String>,
    outcome: String,
    latency_ms: Option<u64>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AuditorToken {
    token: String,
    org_id: Option<String>,
    tenant_id: Option<String>,
    framework: Option<String>,
    note: Option<String>,
    valid_from: u64,
    valid_until: u64,
    created_by: String,
}

#[derive(Deserialize)]
struct CreateAuditorTokenRequest {
    org_id: Option<String>,
    tenant_id: Option<String>,
    framework: Option<String>,
    ttl_secs: u64,
    note: Option<String>,
}

#[derive(Serialize)]
struct CreateAuditorTokenResponse {
    token: AuditorToken,
}

#[derive(Deserialize)]
struct AuditorExportQuery {
    token: String,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ControlChange {
    control_id: String,
    base: Control,
    head: Control,
}

#[derive(Serialize)]
struct PolicyDiff {
    base: PolicySummary,
    head: PolicySummary,
    added_controls: Vec<Control>,
    removed_controls: Vec<Control>,
    changed_controls: Vec<ControlChange>,
}

#[derive(Deserialize)]
struct PolicyReviewRequest {
    reviewer: String,
    decision: String,
    comment: String,
}

#[derive(Serialize)]
struct PolicyReviewResponse {
    id: String,
    policy_id: String,
    reviewer: String,
    decision: String,
    comment: String,
    created_at: u64,
}

#[derive(Serialize)]
struct PolicySummary {
    id: String,
    version: String,
    hash: String,
    created_at: u64,
    framework: String,
    control_count: usize,
}

#[derive(Serialize)]
struct PolicyDetail {
    metadata: RulepackMetadata,
    controls: Vec<Control>,
}

#[derive(Deserialize)]
struct PoliciesQuery {
    framework: Option<String>,
}

#[derive(Deserialize)]
struct PolicyDiffQuery {
    base: String,
    head: String,
}

#[derive(Deserialize)]
struct ControlEvalQuery {
    tenant_id: Option<String>,
    control_id: Option<String>,
    framework: Option<String>,
    passed: Option<bool>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct ControlsQuery {
    framework: Option<String>,
}

#[derive(Deserialize)]
struct ComplianceSummaryQuery {
    tenant_id: String,
    framework: String,
}

#[derive(Serialize)]
struct ComplianceSummary {
    tenant_id: String,
    framework: String,
    latest_burn_id: Option<String>,
    latest_timestamp: Option<u64>,
    total_controls: usize,
    passed_controls: usize,
    failed_controls: usize,
    pass_rate: f64,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn me(ctx: AuthContext) -> Json<MeResponse> {
    // In a real deployment this will be derived from the caller's OIDC/JWT claims
    // and org/tenant mappings inside the compliance graph.
    let orgs = match &ctx.org_id {
        Some(org_id) => vec![OrgSummary {
            org_id: org_id.clone(),
            name: org_id.clone(),
        }],
        None => Vec::new(),
    };

    Json(MeResponse {
        user_id: ctx.user_id,
        orgs,
        roles: ctx.roles,
    })
}

async fn list_burns(
    State(state): State<AppState>,
    _ctx: AuthContext,
    Query(q): Query<BurnsQuery>,
) -> Result<Json<Vec<BurnMetadata>>, (StatusCode, String)> {
    let config = BurnConfig {
        burn_dir: state.burn_dir.clone(),
        auto_sign: false,
        signing_key_id: None,
    };

    let process = BurnProcess::new(config);

    let burns = match process.get_burns(&q.tenant_id, &q.framework) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load burns: {}", e),
            ))
        }
    };

    let metas: Vec<BurnMetadata> = burns.into_iter().map(burn_to_metadata).collect();

    Ok(Json(metas))
}

async fn list_controls(
    _ctx: AuthContext,
    Query(q): Query<ControlsQuery>,
) -> Result<Json<Vec<Control>>, (StatusCode, String)> {
    let path = std::env::var("COMPLIANCE_CONTROLS_FILE")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "COMPLIANCE_CONTROLS_FILE not set".to_string()))?;

    let controls = load_controls_from_file(&path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let filtered: Vec<Control> = match q.framework {
        Some(ref fw) => controls
            .into_iter()
            .filter(|c| c.framework == *fw)
            .collect(),
        None => controls,
    };

    Ok(Json(filtered))
}

async fn compliance_summary(
    State(state): State<AppState>,
    _ctx: AuthContext,
    Query(q): Query<ComplianceSummaryQuery>,
) -> Result<Json<ComplianceSummary>, (StatusCode, String)> {
    let config = BurnConfig {
        burn_dir: state.burn_dir.clone(),
        auto_sign: false,
        signing_key_id: None,
    };

    let process = BurnProcess::new(config);

    let burns = process
        .get_burns(&q.tenant_id, &q.framework)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to load burns: {}", e)))?;

    if burns.is_empty() {
        let summary = ComplianceSummary {
            tenant_id: q.tenant_id.clone(),
            framework: q.framework.clone(),
            latest_burn_id: None,
            latest_timestamp: None,
            total_controls: 0,
            passed_controls: 0,
            failed_controls: 0,
            pass_rate: 0.0,
        };
        return Ok(Json(summary));
    }

    let latest = burns
        .iter()
        .max_by_key(|b| b.timestamp)
        .cloned()
        .unwrap_or_else(|| burns[0].clone());

    let s = latest.summary.clone();

    let summary = ComplianceSummary {
        tenant_id: latest.tenant_id,
        framework: latest.framework,
        latest_burn_id: Some(latest.burn_id),
        latest_timestamp: Some(latest.timestamp),
        total_controls: s.total_controls,
        passed_controls: s.passed_controls,
        failed_controls: s.failed_controls,
        pass_rate: s.pass_rate,
    };

    Ok(Json(summary))
}

async fn list_control_evals(
    _ctx: AuthContext,
    Query(q): Query<ControlEvalQuery>,
) -> Result<Json<Vec<ControlEvalRecord>>, (StatusCode, String)> {
    let path = std::env::var("UTLD_COMPLIANCE_INDEX")
        .unwrap_or_else(|_| "./compliance_index.jsonl".to_string());

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to open compliance index {}: {}", path, e),
            ))
        }
    };

    let reader = std::io::BufReader::new(file);
    let mut results = Vec::new();
    let max = q.limit.unwrap_or(100).min(1000);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read compliance index: {}", e),
                ))
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let rec: ControlEvalRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(ref tenant) = q.tenant_id {
            if rec.tenant_id.as_deref() != Some(tenant.as_str()) {
                continue;
            }
        }

        if let Some(ref cid) = q.control_id {
            if rec.control_id != *cid {
                continue;
            }
        }

        if let Some(ref fw) = q.framework {
            if rec.framework != *fw {
                continue;
            }
        }

        if let Some(passed) = q.passed {
            if rec.passed != passed {
                continue;
            }
        }

        results.push(rec);

        if results.len() >= max {
            break;
        }
    }

    Ok(Json(results))
}

async fn search_evidence(
    _ctx: AuthContext,
    Query(q): Query<EvidenceSearchQuery>,
) -> Result<Json<Vec<EvidenceSearchResult>>, (StatusCode, String)> {
    let db_path = std::env::var("UTLD_DIG_INDEX_DB")
        .unwrap_or_else(|_| "./dig_index.sqlite".to_string());

    let mut query = DigIndexQuery::new();

    if let Some(tenant) = q.tenant_id.clone() {
        query = query.tenant(tenant);
    }
    if let (Some(start), Some(end)) = (q.time_start, q.time_end) {
        query = query.time_range(start, end);
    }
    if let Some(fw) = q.framework.clone() {
        query = query.compliance(fw);
    }
    if let Some(burn_id) = q.burn_id.clone() {
        query = query.burn(burn_id);
    }
    if let Some(decision) = q.policy_decision.clone() {
        query = query.decision(decision);
    }

    let limit = q.limit.unwrap_or(100).min(1000);
    query = query.limit(limit);

    let entries = query
        .execute(&db_path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to query dig index {}: {}", db_path, e)))?;

    let results = entries
        .into_iter()
        .map(|entry| EvidenceSearchResult { entry })
        .collect();

    Ok(Json(results))
}

async fn list_slo_events(
    _ctx: AuthContext,
    Query(q): Query<SloEventsQuery>,
) -> Result<Json<Vec<SloEventRecord>>, (StatusCode, String)> {
    let path = std::env::var("UTLD_SLO_EVENTS")
        .unwrap_or_else(|_| "./slo_events.jsonl".to_string());

    let file = File::open(&path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to open SLO events {}: {}", path, e),
        )
    })?;

    let reader = BufReader::new(file);
    let mut out: Vec<SloEventRecord> = Vec::new();
    let max = q.limit.unwrap_or(200).min(2000);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read SLO events: {}", e),
                ))
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let rec: SloEventRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(ref tenant) = q.tenant_id {
            if rec.tenant_id.as_deref() != Some(tenant.as_str()) {
                continue;
            }
        }
        if let Some(ref comp) = q.component {
            if rec.component != *comp {
                continue;
            }
        }
        if let Some(ref op) = q.operation {
            if rec.operation != *op {
                continue;
            }
        }
        if let Some(ref outcome) = q.outcome {
            if rec.outcome != *outcome {
                continue;
            }
        }

        out.push(rec);
        if out.len() >= max {
            break;
        }
    }

    Ok(Json(out))
}

fn auditor_tokens_path() -> String {
    std::env::var("COMPLIANCE_AUDITOR_TOKENS_FILE")
        .unwrap_or_else(|_| "./auditor_tokens.jsonl".to_string())
}

fn load_auditor_token(token_str: &str) -> Result<AuditorToken, (StatusCode, String)> {
    let path = auditor_tokens_path();
    let file = File::open(&path).map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            format!("auditor token not found (storage {}): {}", path, e),
        )
    })?;

    let reader = BufReader::new(file);
    let mut found: Option<AuditorToken> = None;

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let tok: AuditorToken = match serde_json::from_str(line) {
            Ok(t) => t,
            Err(_) => continue,
        };

        if tok.token == token_str {
            found = Some(tok);
            break;
        }
    }

    let token = found.ok_or_else(|| (StatusCode::NOT_FOUND, "auditor token not found".to_string()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now < token.valid_from || now > token.valid_until {
        return Err((StatusCode::FORBIDDEN, "auditor token expired or not yet valid".to_string()));
    }

    Ok(token)
}

async fn create_auditor_token(
    ctx: AuthContext,
    Json(req): Json<CreateAuditorTokenRequest>,
) -> Result<Json<CreateAuditorTokenResponse>, (StatusCode, String)> {
    let is_auditor = ctx
        .roles
        .iter()
        .any(|r| r == "org_owner" || r == "org_admin" || r == "auditor");
    if !is_auditor {
        return Err((StatusCode::FORBIDDEN, "insufficient role for auditor token".to_string()));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let max_ttl: u64 = 60 * 60 * 24 * 30; // 30 days
    let ttl = req.ttl_secs.min(max_ttl);
    let uid = UID::new();
    let token_str = format!("{:032x}", uid.0);

    let tok = AuditorToken {
        token: token_str,
        org_id: req.org_id.or(ctx.org_id.clone()),
        tenant_id: req.tenant_id,
        framework: req.framework,
        note: req.note,
        valid_from: now,
        valid_until: now + ttl,
        created_by: ctx.user_id,
    };

    let path = auditor_tokens_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to create auditor token dir {}: {}", parent.display(), e),
            ));
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to open auditor token file {}: {}", path, e),
            )
        })?;

    let line = serde_json::to_string(&tok).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize auditor token: {}", e),
        )
    })?;

    if let Err(e) = writeln!(file, "{}", line) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write auditor token: {}", e),
        ));
    }

    Ok(Json(CreateAuditorTokenResponse { token: tok }))
}

async fn auditor_control_evals_export(
    _ctx: AuthContext,
    Query(q): Query<AuditorExportQuery>,
) -> Result<Json<Vec<ControlEvalRecord>>, (StatusCode, String)> {
    let tok = load_auditor_token(&q.token)?;

    let path = std::env::var("UTLD_COMPLIANCE_INDEX")
        .unwrap_or_else(|_| "./compliance_index.jsonl".to_string());

    let file = File::open(&path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to open compliance index {}: {}", path, e),
        )
    })?;
    let reader = BufReader::new(file);

    let mut out: Vec<ControlEvalRecord> = Vec::new();
    let max = q.limit.unwrap_or(500).min(5000);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read compliance index: {}", e),
                ))
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let rec: ControlEvalRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(ref tenant) = tok.tenant_id {
            if rec.tenant_id.as_deref() != Some(tenant.as_str()) {
                continue;
            }
        }
        if let Some(ref fw) = tok.framework {
            if rec.framework != *fw {
                continue;
            }
        }

        out.push(rec);
        if out.len() >= max {
            break;
        }
    }

    Ok(Json(out))
}

async fn auditor_slo_events_export(
    _ctx: AuthContext,
    Query(q): Query<AuditorExportQuery>,
) -> Result<Json<Vec<SloEventRecord>>, (StatusCode, String)> {
    let tok = load_auditor_token(&q.token)?;

    let path = std::env::var("UTLD_SLO_EVENTS")
        .unwrap_or_else(|_| "./slo_events.jsonl".to_string());

    let file = File::open(&path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to open SLO events {}: {}", path, e),
        )
    })?;

    let reader = BufReader::new(file);
    let mut out: Vec<SloEventRecord> = Vec::new();
    let max = q.limit.unwrap_or(500).min(5000);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read SLO events: {}", e),
                ))
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let rec: SloEventRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(ref tenant) = tok.tenant_id {
            if rec.tenant_id.as_deref() != Some(tenant.as_str()) {
                continue;
            }
        }

        out.push(rec);
        if out.len() >= max {
            break;
        }
    }

    Ok(Json(out))
}

fn all_rulepacks() -> Vec<Rulepack> {
    vec![
        soc2_rulepack(),
        hipaa_rulepack(),
        Rulepack::new(
            "AI_SAFETY_2023".to_string(),
            "1.0.0".to_string(),
            ai_safety_controls(),
        ),
    ]
}

fn rulepack_to_summary(rp: &Rulepack) -> PolicySummary {
    let framework = rp
        .controls
        .get(0)
        .map(|c| c.framework.clone())
        .unwrap_or_else(|| "UNKNOWN".to_string());

    PolicySummary {
        id: rp.metadata.id.clone(),
        version: rp.metadata.version.clone(),
        hash: rp.metadata.hash.clone(),
        created_at: rp.metadata.created_at,
        framework,
        control_count: rp.controls.len(),
    }
}

async fn list_policies(
    _ctx: AuthContext,
    Query(q): Query<PoliciesQuery>,
) -> Json<Vec<PolicySummary>> {
    let packs = all_rulepacks();

    let mut out = Vec::new();
    for rp in packs {
        let summary = rulepack_to_summary(&rp);

        if let Some(ref fw) = q.framework {
            if &summary.framework != fw {
                continue;
            }
        }

        out.push(summary);
    }

    Json(out)
}

async fn get_policy(
    _ctx: AuthContext,
    Path(policy_id): Path<String>,
) -> Result<Json<PolicyDetail>, (StatusCode, String)> {
    let packs = all_rulepacks();

    let rp = packs
        .into_iter()
        .find(|p| p.metadata.id == policy_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "policy not found".to_string()))?;

    Ok(Json(PolicyDetail {
        metadata: rp.metadata,
        controls: rp.controls,
    }))
}

async fn policy_diff(
    _ctx: AuthContext,
    Query(q): Query<PolicyDiffQuery>,
) -> Result<Json<PolicyDiff>, (StatusCode, String)> {
    use std::collections::HashMap;

    let packs = all_rulepacks();

    let base_rp = packs
        .iter()
        .find(|p| p.metadata.id == q.base)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("base policy {} not found", q.base)))?;

    let head_rp = packs
        .iter()
        .find(|p| p.metadata.id == q.head)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("head policy {} not found", q.head)))?;

    let mut base_map: HashMap<String, Control> = HashMap::new();
    for c in &base_rp.controls {
        base_map.insert(c.control_id.clone(), c.clone());
    }

    let mut head_map: HashMap<String, Control> = HashMap::new();
    for c in &head_rp.controls {
        head_map.insert(c.control_id.clone(), c.clone());
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for (cid, base_ctrl) in &base_map {
        match head_map.get(cid) {
            None => removed.push(base_ctrl.clone()),
            Some(head_ctrl) => {
                let base_json = serde_json::to_string(base_ctrl).unwrap_or_default();
                let head_json = serde_json::to_string(head_ctrl).unwrap_or_default();
                if base_json != head_json {
                    changed.push(ControlChange {
                        control_id: cid.clone(),
                        base: base_ctrl.clone(),
                        head: head_ctrl.clone(),
                    });
                }
            }
        }
    }

    for (cid, head_ctrl) in &head_map {
        if !base_map.contains_key(cid) {
            added.push(head_ctrl.clone());
        }
    }

    let base_summary = rulepack_to_summary(base_rp);
    let head_summary = rulepack_to_summary(head_rp);

    Ok(Json(PolicyDiff {
        base: base_summary,
        head: head_summary,
        added_controls: added,
        removed_controls: removed,
        changed_controls: changed,
    }))
}

async fn review_policy(
    _ctx: AuthContext,
    Path(policy_id): Path<String>,
    Json(req): Json<PolicyReviewRequest>,
) -> Result<Json<PolicyReviewResponse>, (StatusCode, String)> {
    let packs = all_rulepacks();
    let exists = packs.iter().any(|p| p.metadata.id == policy_id);
    if !exists {
        return Err((StatusCode::NOT_FOUND, "policy not found".to_string()));
    }

    let uid = UID::new();
    let review_id = format!("{:032x}", uid.0);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let response = PolicyReviewResponse {
        id: review_id,
        policy_id: policy_id.clone(),
        reviewer: req.reviewer,
        decision: req.decision,
        comment: req.comment,
        created_at: ts,
    };

    let dir = std::env::var("COMPLIANCE_REVIEWS_DIR")
        .unwrap_or_else(|_| "./compliance_reviews".to_string());

    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create reviews dir {}: {}", dir, e),
        ));
    }

    let path = std::path::Path::new(&dir).join(format!("{}.jsonl", policy_id));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to open reviews file {}: {}", path.display(), e),
            )
        })?;

    let line = serde_json::to_string(&response).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize review: {}", e),
        )
    })?;

    if let Err(e) = writeln!(file, "{}", line) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write review to {}: {}", path.display(), e),
        ));
    }

    Ok(Json(response))
}

async fn get_burn(
    State(state): State<AppState>,
    _ctx: AuthContext,
    Path(burn_id): Path<String>,
    Query(q): Query<PartialBurnsQuery>,
) -> Result<Json<BurnMetadata>, (StatusCode, String)> {
    let config = BurnConfig {
        burn_dir: state.burn_dir.clone(),
        auto_sign: false,
        signing_key_id: None,
    };

    let process = BurnProcess::new(config);

    let burn = match process.load_burn(&burn_id) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("burn not found: {}", e),
            ))
        }
    };

    if let Some(ref tenant) = q.tenant_id {
        if burn.tenant_id != *tenant {
            return Err((StatusCode::NOT_FOUND, "burn tenant mismatch".to_string()));
        }
    }

    if let Some(ref framework) = q.framework {
        if burn.framework != *framework {
            return Err((StatusCode::NOT_FOUND, "burn framework mismatch".to_string()));
        }
    }

    Ok(Json(burn_to_metadata(burn)))
}

fn burn_to_metadata(burn: ComplianceBurn) -> BurnMetadata {
    BurnMetadata {
        burn_id: burn.burn_id,
        timestamp: burn.timestamp,
        tenant_id: burn.tenant_id,
        framework: burn.framework,
        merkle_root: burn.merkle_root,
        record_count: burn.record_count,
        prev_burn_hash: burn.prev_burn_hash,
        burn_hash: burn.burn_hash,
        total_controls: burn.summary.total_controls,
        passed_controls: burn.summary.passed_controls,
        failed_controls: burn.summary.failed_controls,
        pass_rate: burn.summary.pass_rate,
    }
}

fn init_tracing() {
    let filter = EnvFilter::from_default_env();
    let fmt_layer = tracing_subscriber::fmt::layer();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let state = AppState {
        burn_dir: load_burn_dir_from_env(),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/api/me", get(me))
        .route("/api/burns", get(list_burns))
        .route("/api/burns/:burn_id", get(get_burn))
        .route("/api/controls", get(list_controls))
        .route("/api/compliance-summary", get(compliance_summary))
        .route("/api/control-evals", get(list_control_evals))
        .route("/api/policies", get(list_policies))
        .route("/api/policies/diff", get(policy_diff))
        .route("/api/policies/:policy_id", get(get_policy))
        .route("/api/policies/:policy_id/review", post(review_policy))
        .route("/api/evidence/search", get(search_evidence))
        .route("/api/slo/events", get(list_slo_events))
        .route("/api/auditor/tokens", post(create_auditor_token))
        .route("/api/auditor/control-evals", get(auditor_control_evals_export))
        .route("/api/auditor/slo-events", get(auditor_slo_events_export))
        .with_state(state)
        .layer(cors);

    let addr: SocketAddr = std::env::var("COMPLIANCE_CONSOLE_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8092".to_string())
        .parse()
        .expect("invalid COMPLIANCE_CONSOLE_LISTEN_ADDR");

    tracing::info!("compliance_console_api listening on {}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind listener");

    axum::serve(listener, app)
        .await
        .expect("server error");
}

fn load_burn_dir_from_env() -> String {
    std::env::var("COMPLIANCE_BURNS_DIR").unwrap_or_else(|_| "./compliance_burns".to_string())
}
