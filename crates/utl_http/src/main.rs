use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::{extract::State, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use security_tools::{SecurityEvent, SecurityTool, ToolVerdict, Value as SecValue};
use utl_client::UtlClient;
use utld::{NodeRequest, NodeResponse};

#[derive(Clone)]
struct AppState {
    client: Arc<UtlClient>,
    auth_token: Option<String>,
    auth_tenants: BTreeMap<String, String>,
    metrics: Arc<Metrics>,
}

struct Metrics {
    transitions_total: AtomicU64,
    transition_errors_total: AtomicU64,
    dig_seals_total: AtomicU64,
    entropy_bins_total: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            transitions_total: AtomicU64::new(0),
            transition_errors_total: AtomicU64::new(0),
            dig_seals_total: AtomicU64::new(0),
            entropy_bins_total: AtomicU64::new(0),
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct RootsResponse {
    root_ids: Vec<u128>,
}

#[derive(Deserialize)]
struct RegisterRootBody {
    root_id: u128,
    root_hash: String,
    #[serde(default)]
    tx_hook: Option<u128>,
    #[serde(default)]
    params: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct DigBuildRequest {
    root_id: u128,
    file_id: u128,
    time_start: u64,
    time_end: u64,
}

#[derive(Deserialize)]
struct EntropyRequest {
    root_id: u128,
    bin_id: u128,
}

#[derive(Serialize)]
struct DigSummaryResponse {
    root_id: u128,
    file_id: u128,
    merkle_root: String,
    record_count: usize,
}

#[derive(Serialize)]
struct EntropyResponse {
    root_id: u128,
    bin_id: u128,
    local_entropy: f64,
}

#[derive(Deserialize)]
struct RecordTransitionBody {
    entity_id: u128,
    root_id: u128,
    signature: String,
    data: String,
    addr_heap_hash: String,
    hook_hash: String,
    logic_ref: String,
    wall: String,
    #[serde(default)]
    params: BTreeMap<String, String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let socket = std::env::var("UTLD_SOCKET").unwrap_or_else(|_| "/tmp/utld.sock".to_string());
    let client = Arc::new(UtlClient::new(socket));

    let auth_token = std::env::var("UTLD_API_TOKEN").ok();
    let auth_tenants = load_tenant_tokens();
    let metrics = Arc::new(Metrics::new());
    let state = AppState { client, auth_token, auth_tenants, metrics };

    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .route("/roots", get(list_roots).post(register_root))
        .route("/transitions", post(record_transition))
        .route("/dig", post(build_dig))
        .route("/entropy", post(build_entropy))
        .with_state(state);

    let addr: SocketAddr = std::env::var("UTLD_HTTP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .expect("invalid UTLD_HTTP_ADDR");

    tracing::info!("utl_http listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn list_roots(State(state): State<AppState>) -> Result<Json<RootsResponse>, (axum::http::StatusCode, String)> {
    let headers = axum::http::HeaderMap::new();
    let _auth_tenant = check_auth(&state, &headers)?;
    let resp = state
        .client
        .send(&NodeRequest::ListRoots)
        .map_err(internal_err)?;

    match resp {
        NodeResponse::Roots { root_ids } => Ok(Json(RootsResponse { root_ids })),
        other => Err((
            axum::http::StatusCode::BAD_GATEWAY,
            format!("unexpected response from utld: {:?}", other),
        )),
    }
}

async fn register_root(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RegisterRootBody>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let auth_tenant = check_auth(&state, &headers)?;
    if !body.params.contains_key("tenant_id") {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "missing tenant_id in params".to_string(),
        ));
    }
    if let Some(tid) = auth_tenant.as_deref() {
        if let Some(body_tid) = body.params.get("tenant_id") {
            if body_tid != tid {
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    "tenant_id does not match token scope".to_string(),
                ));
            }
        }
    }
    let root_hash = parse_hash32(&body.root_hash).map_err(bad_request)?;
    let tx_hook = body.tx_hook.unwrap_or(body.root_id);

    let req = NodeRequest::RegisterRoot {
        root_id: body.root_id,
        root_hash,
        root_params: body.params,
        tx_hook,
        zk_arc_commit: Vec::new(),
    };

    match state.client.send(&req).map_err(internal_err)? {
        NodeResponse::Ok => {
            state.metrics
                .transitions_total
                .fetch_add(1, Ordering::Relaxed);
            Ok(Json(serde_json::json!({ "status": "ok" })))
        }
        NodeResponse::Error { message } => {
            state.metrics
                .transition_errors_total
                .fetch_add(1, Ordering::Relaxed);
            Err((axum::http::StatusCode::BAD_REQUEST, message))
        }
        other => Err((
            axum::http::StatusCode::BAD_GATEWAY,
            format!("unexpected response from utld: {:?}", other),
        )),
    }
}

async fn build_dig(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<DigBuildRequest>,
) -> Result<Json<DigSummaryResponse>, (axum::http::StatusCode, String)> {
    let _auth_tenant = check_auth(&state, &headers)?;
    let req = NodeRequest::BuildDigFile {
        root_id: body.root_id,
        file_id: body.file_id,
        time_start: body.time_start,
        time_end: body.time_end,
    };

    match state.client.send(&req).map_err(internal_err)? {
        NodeResponse::DigFileSummary {
            root_id,
            file_id,
            merkle_root,
            record_count,
        } => {
            state.metrics.dig_seals_total.fetch_add(1, Ordering::Relaxed);
            state.metrics.transitions_total.fetch_add(1, Ordering::Relaxed);
            Ok(Json(DigSummaryResponse {
                root_id,
                file_id,
                merkle_root: hex::encode(merkle_root),
                record_count,
            }))
        }
        NodeResponse::Error { message } => Err((axum::http::StatusCode::BAD_REQUEST, message)),
        other => Err((
            axum::http::StatusCode::BAD_GATEWAY,
            format!("unexpected response from utld: {:?}", other),
        )),
    }
}

async fn build_entropy(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<EntropyRequest>,
) -> Result<Json<EntropyResponse>, (axum::http::StatusCode, String)> {
    let _auth_tenant = check_auth(&state, &headers)?;
    let req = NodeRequest::BuildEntropyBin {
        root_id: body.root_id,
        bin_id: body.bin_id,
    };

    let raw = state.client.send_raw(&req).map_err(internal_err)?;
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(internal_err)?;

    let status = v
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("");

    if status == "error" {
        let msg = v
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error from utld")
            .to_string();
        return Err((axum::http::StatusCode::BAD_REQUEST, msg));
    }

    if status != "entropy_bin_summary" {
        return Err((
            axum::http::StatusCode::BAD_GATEWAY,
            format!("unexpected response from utld: {}", raw.trim()),
        ));
    }

    let root_id = v
        .get("root_id")
        .and_then(|r| r.as_str())
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(body.root_id);
    let bin_id = v
        .get("bin_id")
        .and_then(|b| b.as_str())
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(body.bin_id);
    let local_entropy = v
        .get("local_entropy")
        .and_then(|le| le.as_f64())
        .unwrap_or(0.0);

    state
        .metrics
        .entropy_bins_total
        .fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .transitions_total
        .fetch_add(1, Ordering::Relaxed);

    Ok(Json(EntropyResponse {
        root_id,
        bin_id,
        local_entropy,
    }))
}

async fn record_transition(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RecordTransitionBody>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let auth_tenant = check_auth(&state, &headers)?;
    let RecordTransitionBody {
        entity_id,
        root_id,
        signature,
        data,
        addr_heap_hash,
        hook_hash,
        logic_ref,
        wall,
        mut params,
    } = body;

    if let Some(tid) = auth_tenant.as_deref() {
        match params.get("tenant_id") {
            Some(p_tid) if p_tid == tid => {}
            Some(_) => {
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    "tenant_id does not match token scope".to_string(),
                ));
            }
            None => {
                return Err((
                    axum::http::StatusCode::BAD_REQUEST,
                    "missing tenant_id in params for tenant-scoped token".to_string(),
                ));
            }
        }
    }

    let signature = hex::decode(&signature).map_err(bad_request)?;
    let data_bytes = data.clone().into_bytes();
    let addr_heap_hash = parse_hash32(&addr_heap_hash).map_err(bad_request)?;
    let hook_hash = parse_hash32(&hook_hash).map_err(bad_request)?;

    if !params.contains_key("event_kind") {
        params.insert("event_kind".to_string(), "http_request".to_string());
    }

    // Run pluggable security sensors to enrich params (e.g. waf_detected, threat_score).
    run_security_sensors(&mut params, &data);

    let req = NodeRequest::RecordTransition {
        entity_id,
        root_id,
        signature,
        data: data_bytes,
        addr_heap_hash,
        p_container: params,
        logic_ref,
        wall,
        hook_hash,
    };

    match state.client.send(&req).map_err(internal_err)? {
        NodeResponse::Ok => Ok(Json(serde_json::json!({ "status": "ok" }))),
        NodeResponse::Error { message } => Err((axum::http::StatusCode::BAD_REQUEST, message)),
        other => Err((
            axum::http::StatusCode::BAD_GATEWAY,
            format!("unexpected response from utld: {:?}", other),
        )),
    }
}

fn parse_hash32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

async fn metrics_handler(State(state): State<AppState>) -> String {
    let t = state.metrics.transitions_total.load(Ordering::Relaxed);
    let te = state.metrics.transition_errors_total.load(Ordering::Relaxed);
    let d = state.metrics.dig_seals_total.load(Ordering::Relaxed);
    let e = state.metrics.entropy_bins_total.load(Ordering::Relaxed);

    format!(
        "transitions_total {}\ntransition_errors_total {}\ndig_seals_total {}\nentropy_bins_total {}\n",
        t, te, d, e
    )
}

fn load_tenant_tokens() -> BTreeMap<String, String> {
    let raw = match std::env::var("UTLD_API_TOKENS") {
        Ok(v) => v,
        Err(_) => return BTreeMap::new(),
    };

    let mut map = BTreeMap::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((tenant, token)) = pair.split_once('=') {
            let tenant = tenant.trim();
            let token = token.trim();
            if !tenant.is_empty() && !token.is_empty() {
                map.insert(tenant.to_string(), token.to_string());
            }
        }
    }

    map
}

fn internal_err(e: impl std::fmt::Debug) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::BAD_GATEWAY, format!("utld error: {:?}", e))
}

fn bad_request(e: impl std::fmt::Display) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::BAD_REQUEST, e.to_string())
}

fn check_auth(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<Option<String>, (axum::http::StatusCode, String)> {
    if state.auth_token.is_none() && state.auth_tenants.is_empty() {
        return Ok(None);
    }

    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !state.auth_tenants.is_empty() {
        let token = auth.strip_prefix("Bearer ").unwrap_or("");

        let mut matched_tenant: Option<String> = None;
        for (tenant_id, expected_token) in &state.auth_tenants {
            if token == expected_token {
                matched_tenant = Some(tenant_id.clone());
                break;
            }
        }

        let tenant = match matched_tenant {
            Some(t) => t,
            None => {
                return Err((
                    axum::http::StatusCode::UNAUTHORIZED,
                    "missing or invalid Authorization bearer token".to_string(),
                ));
            }
        };

        if let Some(header_tid) = headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
        {
            if header_tid != tenant {
                return Err((
                    axum::http::StatusCode::FORBIDDEN,
                    "tenant_id does not match token scope".to_string(),
                ));
            }
        }

        return Ok(Some(tenant));
    }

    if let Some(expected) = &state.auth_token {
        let expected_header = format!("Bearer {}", expected);
        if auth != expected_header {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                "missing or invalid Authorization bearer token".to_string(),
            ));
        }
    }

    Ok(None)
}

fn run_security_sensors(params: &mut BTreeMap<String, String>, raw_data: &str) {
    let kind = params
        .get("event_kind")
        .cloned()
        .unwrap_or_else(|| "record_transition".to_string());

    let mut fields = BTreeMap::new();
    for (k, v) in params.iter() {
        let value = if v.eq_ignore_ascii_case("true") {
            SecValue::Bool(true)
        } else if v.eq_ignore_ascii_case("false") {
            SecValue::Bool(false)
        } else if let Ok(n) = v.parse::<f64>() {
            SecValue::Number(n)
        } else {
            SecValue::String(v.clone())
        };
        fields.insert(k.clone(), value);
    }

    // Include raw payload for tools that inspect body content.
    fields.insert("raw_data".to_string(), SecValue::String(raw_data.to_string()));

    let event = SecurityEvent { kind, fields };

    // Aggregate verdicts from all registered tools.
    let mut max_threat = 0.0f32;
    let mut all_labels: Vec<String> = Vec::new();

    let tools: [&dyn SecurityTool; 2] = [&SqlInjectionTool, &BruteForceAuthTool];

    for tool in tools.iter() {
        let verdict = tool.on_event(&event);
        if verdict.threat_score > max_threat {
            max_threat = verdict.threat_score;
        }
        for label in verdict.labels {
            if !all_labels.iter().any(|l| l == &label) {
                all_labels.push(label);
            }
        }
    }

    if max_threat > 0.0 {
        params
            .entry("threat_score".to_string())
            .or_insert_with(|| format!("{:.3}", max_threat));

        if all_labels.iter().any(|l| l == "sql_injection") {
            params
                .entry("waf_detected".to_string())
                .or_insert_with(|| "sql_injection".to_string());
        }

        if all_labels.iter().any(|l| l == "auth_bruteforce") {
            params
                .entry("auth_risk".to_string())
                .or_insert_with(|| "bruteforce_suspected".to_string());
        }

        if !all_labels.is_empty() {
            let joined = all_labels.join(",");
            params
                .entry("security_labels".to_string())
                .or_insert(joined);
        }
    }
}

struct SqlInjectionTool;

impl SecurityTool for SqlInjectionTool {
    fn on_event(&self, event: &SecurityEvent) -> ToolVerdict {
        if event.kind != "http_request" {
            return ToolVerdict::default();
        }

        let mut verdict = ToolVerdict::default();

        for (field, value) in &event.fields {
            let s = match value {
                SecValue::String(s) => s,
                _ => continue,
            };
            let lower = s.to_ascii_lowercase();
            if lower.contains("' or 1=1") || lower.contains(" or 1=1") || lower.contains("union select") {
                verdict.threat_score = verdict.threat_score.max(0.9);
                if !verdict.labels.iter().any(|l| l == "sql_injection") {
                    verdict.labels.push("sql_injection".to_string());
                }
                verdict.extra = serde_json::json!({
                    "field": field,
                    "snippet": s,
                });
                break;
            }
        }

        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    #[test]
    fn tenant_token_auth_succeeds_and_returns_tenant() {
        std::env::set_var("UTLD_API_TOKENS", "tenantA=tokenA");
        let auth_tenants = load_tenant_tokens();
        assert_eq!(auth_tenants.get("tenantA").unwrap(), "tokenA");

        let state = AppState {
            client: Arc::new(UtlClient::new("/tmp/utld-test.sock")),
            auth_token: None,
            auth_tenants,
            metrics: Arc::new(Metrics::new()),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer tokenA"),
        );
        headers.insert("x-tenant-id", HeaderValue::from_static("tenantA"));

        let tenant = check_auth(&state, &headers).expect("auth ok");
        assert_eq!(tenant.as_deref(), Some("tenantA"));
    }

    #[test]
    fn tenant_token_auth_forbidden_on_mismatched_tenant_header() {
        std::env::set_var("UTLD_API_TOKENS", "tenantA=tokenA");
        let auth_tenants = load_tenant_tokens();
        let state = AppState {
            client: Arc::new(UtlClient::new("/tmp/utld-test.sock")),
            auth_token: None,
            auth_tenants,
            metrics: Arc::new(Metrics::new()),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer tokenA"),
        );
        headers.insert("x-tenant-id", HeaderValue::from_static("tenantB"));

        let res = check_auth(&state, &headers);
        assert!(res.is_err());
        let (status, _) = res.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
struct BruteForceAuthTool;

impl SecurityTool for BruteForceAuthTool {
    fn on_event(&self, event: &SecurityEvent) -> ToolVerdict {
        if event.kind != "auth_attempt" {
            return ToolVerdict::default();
        }

        let mut verdict = ToolVerdict::default();

        let failed = event
            .fields
            .get("failed_attempts_last_10_min")
            .and_then(|v| match v {
                SecValue::Number(n) => Some(*n),
                _ => None,
            })
            .unwrap_or(0.0);

        let success = event
            .fields
            .get("success")
            .and_then(|v| match v {
                SecValue::Bool(b) => Some(*b),
                SecValue::String(s) => Some(s.eq_ignore_ascii_case("true")),
                _ => None,
            })
            .unwrap_or(false);

        if !success && failed >= 5.0 {
            verdict.threat_score = if failed >= 10.0 { 0.95 } else { 0.75 };
            verdict.labels.push("auth_bruteforce".to_string());

            let ip = event
                .fields
                .get("client_ip")
                .and_then(|v| match v {
                    SecValue::String(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "<unknown-ip>".to_string());
            let actor = event
                .fields
                .get("actor_did")
                .and_then(|v| match v {
                    SecValue::String(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "<unknown-actor>".to_string());

            verdict.extra = serde_json::json!({
                "failed_attempts_last_10_min": failed,
                "client_ip": ip,
                "actor_did": actor,
            });
        }

        verdict
    }
}
