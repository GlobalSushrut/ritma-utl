use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    async_trait,
    extract::{FromRequestParts, Path, Query, State},
    http::{request::Parts, StatusCode},
    routing::{get, post},
    Json, Router,
};
use core_types::UID;
use dig_index::{DigIndexEntry, DigIndexQuery};
use node_keystore::NodeKeystore;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Clone, Debug, Serialize)]
struct NodeInfo {
    id: String,
    org_id: String,
    tenant_id: Option<String>,
    hostname: Option<String>,
    labels: HashMap<String, String>,
    capabilities: Vec<String>,
    status: String,
    utld_version: Option<String>,
    policy_version: Option<String>,
    last_heartbeat_at: Option<u64>,
}

#[derive(Clone)]
struct AppState {
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    enrollment_tokens: Arc<RwLock<Vec<EnrollmentToken>>>,
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

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct OrgSummary {
    org_id: String,
}

#[derive(Serialize)]
struct MeResponse {
    user_id: String,
    orgs: Vec<OrgSummary>,
    roles: Vec<String>,
}

#[derive(Deserialize)]
struct RegisterNodeRequest {
    org_id: String,
    tenant_id: Option<String>,
    node_id: Option<String>,
    hostname: Option<String>,
    labels: Option<HashMap<String, String>>,
    capabilities: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    status: Option<String>,
    utld_version: Option<String>,
    policy_version: Option<String>,
}

#[derive(Deserialize)]
struct ListNodesQuery {
    org_id: Option<String>,
    tenant_id: Option<String>,
}

#[derive(Serialize)]
struct DashboardSummary {
    org_id: Option<String>,
    total_nodes: usize,
    tenants: usize,
    online_nodes: usize,
    offline_nodes: usize,
}

#[derive(Deserialize)]
struct DashboardQuery {
    org_id: Option<String>,
}

#[derive(Serialize)]
struct TenantSummary {
    id: String,
    node_count: usize,
}

#[derive(Clone, Serialize)]
struct EnrollmentToken {
    id: String,
    created_at: u64,
    note: Option<String>,
}

#[derive(Deserialize)]
struct CreateEnrollmentTokenRequest {
    note: Option<String>,
}

#[derive(Serialize)]
struct EnrollmentTokensResponse {
    tokens: Vec<EnrollmentToken>,
}

#[derive(Serialize)]
struct ConfigInfo {
    node_controller_listen_addr: String,
    utld_compliance_index_path: String,
    utld_slo_events_path: String,
    utld_decision_events_path: String,
    utld_dig_index_db_path: String,
    node_log_paths: Vec<String>,
}

#[derive(Serialize)]
struct WalletInfo {
    key_id: String,
    key_hash: String,
    label: Option<String>,
}

#[derive(Deserialize)]
struct LogsQuery {
    paths: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct LogChunk {
    path: String,
    lines: Vec<String>,
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

#[derive(Deserialize)]
struct IncidentQuery {
    tenant_id: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize, Deserialize, Clone)]
struct DecisionEventRecord {
    ts: u64,
    tenant_id: Option<String>,
    root_id: String,
    entity_id: String,
    event_kind: String,
    policy_decision: String,
    snark_high_threat_merkle_status: Option<String>,
    policy_commit_id: Option<String>,
}

#[derive(Deserialize)]
struct EvidenceSearchQuery {
    tenant_id: Option<String>,
    policy_decision: Option<String>,
    time_start: Option<u64>,
    time_end: Option<u64>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct EvidenceSearchResult {
    entry: DigIndexEntry,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn me(ctx: AuthContext) -> Json<MeResponse> {
    let orgs = match &ctx.org_id {
        Some(id) => vec![OrgSummary { org_id: id.clone() }],
        None => Vec::new(),
    };

    Json(MeResponse {
        user_id: ctx.user_id,
        orgs,
        roles: ctx.roles,
    })
}

async fn register_node(
    State(state): State<AppState>,
    _ctx: AuthContext,
    Json(req): Json<RegisterNodeRequest>,
) -> Result<Json<NodeInfo>, (StatusCode, String)> {
    let now = now_secs();
    let uid = if let Some(id_str) = req.node_id {
        // If a caller supplies a node_id, hash it into a u128 for UID.
        let hash = xxhash_rust::xxh3::xxh3_128(id_str.as_bytes());
        format!("{:032x}", hash)
    } else {
        format!("{:032x}", UID::new().0)
    };

    let labels = req.labels.unwrap_or_default();
    let capabilities = req.capabilities.unwrap_or_default();

    let info = NodeInfo {
        id: uid.clone(),
        org_id: req.org_id,
        tenant_id: req.tenant_id,
        hostname: req.hostname,
        labels,
        capabilities,
        status: "online".to_string(),
        utld_version: None,
        policy_version: None,
        last_heartbeat_at: Some(now),
    };

    let mut guard = state.nodes.write().await;
    guard.insert(uid, info.clone());

    Ok(Json(info))
}

async fn node_heartbeat(
    State(state): State<AppState>,
    _ctx: AuthContext,
    Path(id): Path<String>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<NodeInfo>, (StatusCode, String)> {
    let mut guard = state.nodes.write().await;
    let node = guard.get_mut(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("node {} not found", id),
        )
    })?;

    if let Some(status) = req.status {
        node.status = status;
    }
    if let Some(v) = req.utld_version {
        node.utld_version = Some(v);
    }
    if let Some(v) = req.policy_version {
        node.policy_version = Some(v);
    }
    node.last_heartbeat_at = Some(now_secs());

    Ok(Json(node.clone()))
}

async fn list_nodes(
    State(state): State<AppState>,
    _ctx: AuthContext,
    Query(q): Query<ListNodesQuery>,
) -> Json<Vec<NodeInfo>> {
    let guard = state.nodes.read().await;
    let mut out = Vec::new();

    for node in guard.values() {
        if let Some(ref org) = q.org_id {
            if &node.org_id != org {
                continue;
            }
        }
        if let Some(ref tenant) = q.tenant_id {
            if node.tenant_id.as_deref() != Some(tenant.as_str()) {
                continue;
            }
        }
        out.push(node.clone());
    }

    Json(out)
}

async fn get_node(
    State(state): State<AppState>,
    _ctx: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<NodeInfo>, (StatusCode, String)> {
    let guard = state.nodes.read().await;
    let node = guard.get(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("node {} not found", id),
        )
    })?;

    Ok(Json(node.clone()))
}

async fn dashboard(
    State(state): State<AppState>,
    _ctx: AuthContext,
    Query(q): Query<DashboardQuery>,
) -> Json<DashboardSummary> {
    use std::collections::HashSet;

    let guard = state.nodes.read().await;
    let mut total = 0usize;
    let mut online = 0usize;
    let mut offline = 0usize;
    let mut tenants: HashSet<String> = HashSet::new();

    for node in guard.values() {
        if let Some(ref org) = q.org_id {
            if &node.org_id != org {
                continue;
            }
        }
        total += 1;
        if node.status == "online" {
            online += 1;
        } else {
            offline += 1;
        }
        if let Some(ref t) = node.tenant_id {
            tenants.insert(t.clone());
        }
    }

    Json(DashboardSummary {
        org_id: q.org_id,
        total_nodes: total,
        tenants: tenants.len(),
        online_nodes: online,
        offline_nodes: offline,
    })
}

async fn list_tenants(
    State(state): State<AppState>,
    _ctx: AuthContext,
) -> Json<Vec<TenantSummary>> {
    use std::collections::HashMap as Map;

    let guard = state.nodes.read().await;
    let mut counts: Map<String, usize> = Map::new();
    for node in guard.values() {
        if let Some(ref t) = node.tenant_id {
            *counts.entry(t.clone()).or_insert(0) += 1;
        }
    }

    let mut out = Vec::new();
    for (id, count) in counts {
        out.push(TenantSummary { id, node_count: count });
    }

    Json(out)
}

async fn list_enrollment_tokens(
    State(state): State<AppState>,
    _ctx: AuthContext,
) -> Json<EnrollmentTokensResponse> {
    let guard = state.enrollment_tokens.read().await;
    Json(EnrollmentTokensResponse {
        tokens: guard.clone(),
    })
}

async fn create_enrollment_token(
    State(state): State<AppState>,
    _ctx: AuthContext,
    Json(req): Json<CreateEnrollmentTokenRequest>,
) -> Json<EnrollmentToken> {
    let now = now_secs();
    let id = format!("{:032x}", UID::new().0);
    let tok = EnrollmentToken {
        id,
        created_at: now,
        note: req.note,
    };

    let mut guard = state.enrollment_tokens.write().await;
    guard.push(tok.clone());

    Json(tok)
}

async fn get_config() -> Json<ConfigInfo> {
    let addr = std::env::var("NODE_CONTROLLER_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8093".to_string());
    let compliance_index = std::env::var("UTLD_COMPLIANCE_INDEX")
        .unwrap_or_else(|_| "./compliance_index.jsonl".to_string());
    let slo_events = std::env::var("UTLD_SLO_EVENTS")
        .unwrap_or_else(|_| "./slo_events.jsonl".to_string());
    let decision_events = std::env::var("UTLD_DECISION_EVENTS")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());
    let dig_index_db = std::env::var("UTLD_DIG_INDEX_DB")
        .unwrap_or_else(|_| "./dig_index.sqlite".to_string());
    let log_paths_raw = std::env::var("NODE_LOG_PATHS")
        .unwrap_or_else(|_| "./utld.log".to_string());
    let node_log_paths: Vec<String> = log_paths_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Json(ConfigInfo {
        node_controller_listen_addr: addr,
        utld_compliance_index_path: compliance_index,
        utld_slo_events_path: slo_events,
        utld_decision_events_path: decision_events,
        utld_dig_index_db_path: dig_index_db,
        node_log_paths,
    })
}

async fn get_wallet() -> Result<Json<WalletInfo>, (StatusCode, String)> {
    let key_id = std::env::var("RITMA_KEY_ID")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "RITMA_KEY_ID not set".to_string()))?;

    // Prefer keystore metadata if available.
    let (key_hash, label) = if let Ok(ks) = NodeKeystore::from_env() {
        match ks.metadata_for(&key_id) {
            Ok(meta) => (meta.key_hash, meta.label),
            Err(e) => {
                tracing::warn!(
                    target = "node_controller_api::wallet",
                    "failed to load key metadata from node keystore (key_id={}): {}",
                    key_id,
                    e,
                );
                let key_hash = std::env::var("RITMA_KEY_HASH")
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "RITMA_KEY_HASH not set".to_string()))?;
                let label = std::env::var("RITMA_KEY_LABEL").ok();
                (key_hash, label)
            }
        }
    } else {
        let key_hash = std::env::var("RITMA_KEY_HASH")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "RITMA_KEY_HASH not set".to_string()))?;
        let label = std::env::var("RITMA_KEY_LABEL").ok();
        (key_hash, label)
    };

    Ok(Json(WalletInfo {
        key_id,
        key_hash,
        label,
    }))
}

async fn get_logs(
    Query(q): Query<LogsQuery>,
) -> Result<Json<Vec<LogChunk>>, (StatusCode, String)> {
    let paths_raw = if let Some(p) = q.paths {
        p
    } else {
        std::env::var("NODE_LOG_PATHS")
            .unwrap_or_else(|_| "./utld.log".to_string())
    };

    let paths: Vec<String> = paths_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let limit = q.limit.unwrap_or(200).min(5000);
    let mut chunks = Vec::new();

    for path in paths {
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        let mut all_lines: Vec<String> = Vec::new();
        for line_res in reader.lines() {
            match line_res {
                Ok(l) => all_lines.push(l),
                Err(_) => continue,
            }
        }

        let start = if all_lines.len() > limit {
            all_lines.len() - limit
        } else {
            0
        };
        let lines = all_lines[start..].to_vec();

        chunks.push(LogChunk { path, lines });
    }

    Ok(Json(chunks))
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

async fn list_incidents(
    _ctx: AuthContext,
    Query(q): Query<IncidentQuery>,
) -> Result<Json<Vec<DecisionEventRecord>>, (StatusCode, String)> {
    let path = std::env::var("UTLD_DECISION_EVENTS")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());

    let file = File::open(&path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to open decision events {}: {}", path, e),
        )
    })?;

    let reader = BufReader::new(file);
    let mut incidents: Vec<DecisionEventRecord> = Vec::new();
    let max = q.limit.unwrap_or(200).min(2000);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read decision events: {}", e),
                ))
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let ev: DecisionEventRecord = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if let Some(ref tid) = q.tenant_id {
            if ev.tenant_id.as_deref() != Some(tid.as_str()) {
                continue;
            }
        }

        let is_deny = ev.policy_decision == "deny";
        let is_high_threat = matches!(
            ev.snark_high_threat_merkle_status.as_deref(),
            Some("invalid") | Some("error") | Some("high")
        );

        if is_deny || is_high_threat {
            incidents.push(ev);
        }
    }

    incidents.sort_by_key(|e| e.ts);
    incidents.reverse();
    incidents.truncate(max);

    Ok(Json(incidents))
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
    if let Some(decision) = q.policy_decision.clone() {
        query = query.decision(decision);
    }

    let limit = q.limit.unwrap_or(100).min(1000);
    query = query.limit(limit);

    let entries = query
        .execute(&db_path)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to query dig index {}: {}", db_path, e),
            )
        })?;

    let results = entries
        .into_iter()
        .map(|entry| EvidenceSearchResult { entry })
        .collect();

    Ok(Json(results))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
        nodes: Arc::new(RwLock::new(HashMap::new())),
        enrollment_tokens: Arc::new(RwLock::new(Vec::new())),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/api/me", get(me))
        .route("/api/dashboard", get(dashboard))
        .route("/api/tenants", get(list_tenants))
        .route("/api/nodes", get(list_nodes).post(register_node))
        .route("/api/nodes/:id", get(get_node))
        .route("/api/nodes/:id/heartbeat", post(node_heartbeat))
        .route("/api/enrollment/tokens", get(list_enrollment_tokens).post(create_enrollment_token))
        .route("/api/config", get(get_config))
        .route("/api/wallet", get(get_wallet))
        .route("/api/logs", get(get_logs))
        .route("/api/slo/events", get(list_slo_events))
        .route("/api/incidents", get(list_incidents))
        .route("/api/evidence/search", get(search_evidence))
        .with_state(state)
        .layer(cors);

    let addr: SocketAddr = std::env::var("NODE_CONTROLLER_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8093".to_string())
        .parse()
        .expect("invalid NODE_CONTROLLER_LISTEN_ADDR");

    tracing::info!("node_controller_api listening on {}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind listener");

    axum::serve(listener, app)
        .await
        .expect("server error");
}
