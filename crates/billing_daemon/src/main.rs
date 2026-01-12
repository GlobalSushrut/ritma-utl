use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use biz_api::{
    compute_invoice_draft_for_month, MetricKind, PricingRule, ProductId, TenantConfig, UsageEvent,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// One billing period ~= 30 days, expressed in seconds.
const BILLING_PERIOD_SECS: u64 = 30 * 24 * 60 * 60;

type UsageKey = (String, String, u64, MetricKind); // (tenant_id, plan_id, period_idx, metric)

type UsageTotals = HashMap<UsageKey, u64>;

#[derive(Clone)]
struct AppState {
    pricing_rules: Arc<Vec<PricingRule>>,
    usage_totals: Arc<Mutex<UsageTotals>>,
    tenant_plans: Arc<HashMap<String, String>>, // tenant_id -> plan_id
    default_plan_id: String,
}

#[derive(Deserialize)]
struct InvoiceQuery {
    tenant_id: String,
    period_idx: u64,
    #[serde(default = "default_currency")]
    currency: String,
    #[serde(default)]
    base_price_cents: Option<u64>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

fn default_currency() -> String {
    "usd".to_string()
}

// POST /ingest-usage  Body: UsageEvent
async fn ingest_usage(
    State(state): State<AppState>,
    Json(ev): Json<UsageEvent>,
) -> Json<serde_json::Value> {
    let plan_id = state
        .tenant_plans
        .get(&ev.tenant_id)
        .cloned()
        .unwrap_or_else(|| state.default_plan_id.clone());

    let period_idx = ev.ts / BILLING_PERIOD_SECS;

    let key = (ev.tenant_id.clone(), plan_id, period_idx, ev.metric);

    let mut totals = state.usage_totals.lock().await;
    *totals.entry(key).or_insert(0) += ev.quantity;

    Json(serde_json::json!({ "status": "ok" }))
}

// GET /invoice-draft?tenant_id=...&period_idx=...
async fn invoice_draft(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<InvoiceQuery>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let plan_id = state
        .tenant_plans
        .get(&q.tenant_id)
        .cloned()
        .unwrap_or_else(|| state.default_plan_id.clone());

    let period_start_ts = q.period_idx.saturating_mul(BILLING_PERIOD_SECS);
    let period_end_ts = period_start_ts + BILLING_PERIOD_SECS - 1;

    let totals = state.usage_totals.lock().await;

    let mut by_metric: HashMap<MetricKind, u64> = HashMap::new();
    for ((tenant_id, stored_plan, period_idx, metric), qty) in totals.iter() {
        if *tenant_id == q.tenant_id && *stored_plan == plan_id && *period_idx == q.period_idx {
            let entry = by_metric.entry(*metric).or_insert(0);
            *entry = entry.saturating_add(*qty);
        }
    }

    if by_metric.is_empty() {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            format!(
                "no usage found for tenant {} in period {}",
                q.tenant_id, q.period_idx
            ),
        ));
    }

    let mut usage_vec: Vec<(ProductId, MetricKind, u64)> = Vec::new();
    for (metric, qty) in by_metric {
        usage_vec.push((ProductId::ManagedUtldClusters, metric, qty));
    }

    let base_price_cents = q.base_price_cents.unwrap_or(0);

    let draft = compute_invoice_draft_for_month(
        &q.tenant_id,
        &plan_id,
        period_start_ts,
        period_end_ts,
        &q.currency,
        base_price_cents,
        &usage_vec,
        &state.pricing_rules,
    );

    Ok(Json(serde_json::to_value(draft).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize invoice draft: {e}"),
        )
    })?))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

fn load_pricing_rules_from_env() -> Vec<PricingRule> {
    let path = match std::env::var("BILLING_PRICING_FILE") {
        Ok(p) if !p.is_empty() => p,
        _ => return Vec::new(),
    };

    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<Vec<PricingRule>>(&content) {
            Ok(rules) => rules,
            Err(e) => {
                eprintln!("failed to parse pricing rules {path}: {e}");
                Vec::new()
            }
        },
        Err(e) => {
            eprintln!("failed to read pricing rules {path}: {e}");
            Vec::new()
        }
    }
}

fn load_tenant_plans_from_env() -> HashMap<String, String> {
    let path = match std::env::var("BILLING_TENANTS_FILE") {
        Ok(p) if !p.is_empty() => p,
        _ => return HashMap::new(),
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to read tenants file {path}: {e}");
            return HashMap::new();
        }
    };

    let tenants: Vec<TenantConfig> = match serde_json::from_str(&content) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("failed to parse tenants file {path}: {e}");
            return HashMap::new();
        }
    };

    let mut map = HashMap::new();
    for t in tenants {
        map.insert(t.tenant_id, t.plan.plan_id);
    }
    map
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

    let pricing_rules = load_pricing_rules_from_env();
    let tenant_plans = load_tenant_plans_from_env();

    let default_plan_id =
        std::env::var("BILLING_DEFAULT_PLAN_ID").unwrap_or_else(|_| "pilot_free".to_string());

    let state = AppState {
        pricing_rules: Arc::new(pricing_rules),
        usage_totals: Arc::new(Mutex::new(HashMap::new())),
        tenant_plans: Arc::new(tenant_plans),
        default_plan_id,
    };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/ingest-usage", post(ingest_usage))
        .route("/invoice-draft", get(invoice_draft))
        .with_state(state);

    let addr: SocketAddr = std::env::var("BILLING_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8090".to_string())
        .parse()
        .expect("invalid BILLING_LISTEN_ADDR");

    tracing::info!("billing_daemon listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind billing_daemon listener");

    axum::serve(listener, app.into_make_service())
        .await
        .expect("server error");
}
