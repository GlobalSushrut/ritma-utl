mod metrics;
mod tls_transport;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::tls_transport::PeerDid;
use axum::{
    extract::{Extension, Query, State},
    routing::{get, post},
    Json, Router,
};
use biz_api::UsageEvent;
use compliance_index::ControlEvalRecord;
use dig_index::DigIndexEntry;
use evidence_package::{EvidencePackageManifest, PackageScope, PackageSigner, SigningKey};
use node_keystore::{KeystoreKey, NodeKeystore};
use opentelemetry::global;
use opentelemetry_sdk::trace as sdktrace;
use security_events::DecisionEvent;
use security_kit::compliance::EvidenceBuilder;
use security_kit::containers::ParamBundle;
use security_kit::reporting::SecurityReport;
use security_kit::{SecurityKit, SecurityKitError};
use security_os::MtlsConfig;
use security_tools::{SecurityEvent, SecurityTool, ToolVerdict, Value as SecValue};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::layer::{Context as LayerContext, Layer};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Registry;
use utl_client::UtlClient;
use utld::{NodeRequest, NodeResponse};

type UsageTotals = BTreeMap<(String, String, String), u64>;

#[derive(Clone)]
struct AppState {
    client: Arc<UtlClient>,
    auth_token: Option<String>,
    auth_tenants: BTreeMap<String, String>,
    metrics: Arc<Metrics>,
    usage_totals: Arc<Mutex<UsageTotals>>,
}

fn load_http_mtls_config_from_env() -> Option<MtlsConfig> {
    let ca_bundle_path = std::env::var("UTL_HTTP_TLS_CA").ok()?;
    let cert_path = std::env::var("UTL_HTTP_TLS_CERT").ok()?;
    let key_path = std::env::var("UTL_HTTP_TLS_KEY").ok()?;

    let require_client_auth = std::env::var("UTL_HTTP_TLS_REQUIRE_CLIENT_AUTH")
        .ok()
        .map(|v| {
            let v = v.to_lowercase();
            !(v == "0" || v == "false" || v == "no")
        })
        .unwrap_or(true);

    Some(MtlsConfig {
        ca_bundle_path,
        cert_path,
        key_path,
        require_client_auth,
    })
}

#[derive(Deserialize, Debug)]
struct DecisionSearchQuery {
    tenant_id: Option<String>,
    event_kind: Option<String>,
    policy_commit_id: Option<String>,
    policy_name: Option<String>,
    policy_decision: Option<String>,
    text: Option<String>,
    #[serde(default)]
    ts_start: Option<u64>,
    #[serde(default)]
    ts_end: Option<u64>,
    #[serde(default = "default_limit")] // default limit
    limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Serialize)]
struct DecisionSearchResult {
    event: DecisionEvent,
}

async fn search_decisions(
    Query(q): Query<DecisionSearchQuery>,
) -> Result<Json<Vec<DecisionSearchResult>>, (axum::http::StatusCode, String)> {
    let path = std::env::var("UTLD_DECISION_EVENTS")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());
    let file = File::open(&path)
        .map_err(|e| bad_request(format!("failed to open decision events {path}: {e}")))?;
    let reader = std::io::BufReader::new(file);

    let mut out = Vec::new();
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("search_decisions: failed to read line: {e}");
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let ev: DecisionEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("search_decisions: failed to parse DecisionEvent: {e}");
                continue;
            }
        };

        if let Some(ref tid) = q.tenant_id {
            if ev.tenant_id.as_deref() != Some(tid.as_str()) {
                continue;
            }
        }
        if let Some(ref kind) = q.event_kind {
            if ev.event_kind != *kind {
                continue;
            }
        }
        if let Some(ref cid) = q.policy_commit_id {
            if ev.policy_commit_id.as_deref() != Some(cid.as_str()) {
                continue;
            }
        }
        if let Some(ref name) = q.policy_name {
            if ev.policy_name.as_deref() != Some(name.as_str()) {
                continue;
            }
        }
        if let Some(ref dec) = q.policy_decision {
            if ev.policy_decision != *dec {
                continue;
            }
        }
        if let Some(ts_start) = q.ts_start {
            if ev.ts < ts_start {
                continue;
            }
        }
        if let Some(ts_end) = q.ts_end {
            if ev.ts > ts_end {
                continue;
            }
        }
        if let Some(ref txt) = q.text {
            let haystacks = [
                ev.policy_name.as_deref().unwrap_or(""),
                ev.policy_decision.as_str(),
                ev.root_id.as_str(),
                ev.entity_id.as_str(),
            ];
            if !haystacks.iter().any(|h| h.contains(txt)) {
                continue;
            }
        }

        out.push(DecisionSearchResult { event: ev });
        if out.len() >= q.limit {
            break;
        }
    }

    Ok(Json(out))
}

// ==== SecurityKit control-plane handlers ====

async fn securitykit_connectors_dry_run(
    Json(req): Json<SecurityKitDryRunRequest>,
) -> Result<Json<SecurityKitDryRunResponse>, (axum::http::StatusCode, String)> {
    if req.connectors.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "connectors array must not be empty".to_string(),
        ));
    }

    let mut builder = SecurityKit::builder();
    for name in &req.connectors {
        match name.to_lowercase().as_str() {
            "kubernetes" | "k8s" => {
                builder = builder.add_kubernetes_connector("k8s-cluster");
            }
            "aws" => {
                builder = builder.add_aws_connector("aws-account");
            }
            "gcp" => {
                builder = builder.add_gcp_connector("gcp-project");
            }
            "storage" | "s3" | "gcs" | "azure_blob" => {
                builder = builder.add_storage_connector("storage");
            }
            other => {
                return Err((
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("unknown connector: {other}"),
                ));
            }
        }
    }

    match builder.dry_run_connectors(&req.params) {
        Ok(()) => Ok(Json(SecurityKitDryRunResponse { status: "ok" })),
        Err(SecurityKitError::ConnectorError(msg)) => {
            Err((axum::http::StatusCode::BAD_REQUEST, msg))
        }
        Err(e) => Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

async fn securitykit_evidence_package(
    Json(req): Json<EvidencePackageRequest>,
) -> Result<Json<EvidencePackageManifest>, (axum::http::StatusCode, String)> {
    // Parse scope similar to utl_cli evidence_package_commands.
    let scope = match req.scope_type.to_lowercase().as_str() {
        "policy_commit" | "commit" => PackageScope::PolicyCommit {
            commit_id: req.scope_id.clone(),
            framework: req.framework.clone(),
        },
        "burn" => {
            let fw = req.framework.clone().ok_or_else(|| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    "framework required for burn scope".to_string(),
                )
            })?;
            PackageScope::ComplianceBurn {
                burn_id: req.scope_id.clone(),
                framework: fw,
            }
        }
        "time_range" | "time" => {
            let parts: Vec<&str> = req.scope_id.split(':').collect();
            if parts.len() != 2 {
                return Err((
                    axum::http::StatusCode::BAD_REQUEST,
                    "time_range scope_id must be start:end".to_string(),
                ));
            }
            let start = parts[0].parse::<u64>().map_err(|e| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("invalid start time: {e}"),
                )
            })?;
            let end = parts[1].parse::<u64>().map_err(|e| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("invalid end time: {e}"),
                )
            })?;
            PackageScope::TimeRange {
                time_start: start,
                time_end: end,
                framework: req.framework.clone(),
            }
        }
        other => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                format!("unsupported scope_type: {other}"),
            ));
        }
    };

    let mut builder = EvidenceBuilder::new(req.tenant.clone(), scope);
    if let Some(fw) = &req.framework {
        builder = builder.with_framework(fw.clone());
    }

    let mut manifest = builder
        .build()
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if req.sign {
        let mut signed = false;

        // Prefer node keystore if configured.
        if let Ok(key_id) = std::env::var("RITMA_KEY_ID") {
            if let Err(msg) = enforce_key_governance_for_signing(&key_id).await {
                return Err((axum::http::StatusCode::FORBIDDEN, msg));
            }

            match NodeKeystore::from_env().and_then(|ks| ks.key_for_signing(&key_id)) {
                Ok(keystore_key) => {
                    let signing_key = match keystore_key {
                        KeystoreKey::HmacSha256(bytes) => SigningKey::HmacSha256(bytes),
                        KeystoreKey::Ed25519(sk) => SigningKey::Ed25519(sk),
                    };
                    let signer = PackageSigner::new(signing_key, "utl_http".to_string());
                    signer.sign(&mut manifest).map_err(|e| {
                        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                    })?;
                    signed = true;
                }
                Err(e) => {
                    tracing::warn!(
                        target = "utl_http::keystore",
                        "failed to load signing key from node keystore (key_id={}): {}",
                        key_id,
                        e,
                    );
                }
            }
        }

        // Fallback to legacy env-based signing if keystore was not used.
        if !signed {
            match PackageSigner::from_env("UTLD_PACKAGE_SIG_KEY", "utl_http".to_string()) {
                Ok(signer) => {
                    signer.sign(&mut manifest).map_err(|e| {
                        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                    })?;
                }
                Err(e) => {
                    return Err((
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to load signing key: {e}"),
                    ));
                }
            }
        }
    }

    // Best-effort telemetry to ritma_cloud: send an evidence summary if configured.
    let manifest_for_cloud = manifest.clone();
    tokio::spawn(async move {
        if let Err(e) = send_evidence_to_ritma_cloud(manifest_for_cloud).await {
            tracing::warn!(
                target = "utl_http::ritma_cloud",
                "failed to send evidence telemetry: {}",
                e
            );
        }
    });

    Ok(Json(manifest))
}

#[derive(Serialize)]
struct RitmaCloudEvidenceSummary {
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

fn ritma_cloud_base_url() -> Option<String> {
    std::env::var("RITMA_CLOUD_URL").ok()
}

fn ritma_cloud_org_id() -> Option<String> {
    std::env::var("RITMA_CLOUD_ORG_ID").ok()
}

fn ritma_cloud_node_id() -> String {
    std::env::var("RITMA_NODE_ID").unwrap_or_else(|_| "local-node".to_string())
}

fn key_governance_enforcement_enabled() -> bool {
    match std::env::var("RITMA_ENFORCE_KEY_GOVERNANCE") {
        Ok(v) => {
            let v = v.to_lowercase();
            !(v == "0" || v == "false" || v == "no" || v.is_empty())
        }
        Err(_) => false,
    }
}

async fn enforce_key_governance_for_signing(key_id: &str) -> Result<(), String> {
    if !key_governance_enforcement_enabled() {
        return Ok(());
    }

    let base = match ritma_cloud_base_url() {
        Some(b) => b,
        None => return Ok(()),
    };
    let org_id = match ritma_cloud_org_id() {
        Some(id) => id,
        None => return Ok(()),
    };

    let client = reqwest::Client::new();
    let mut req = client.get(format!("{}/keys/{}", base.trim_end_matches('/'), key_id,));

    if let Ok(api_key) = std::env::var("RITMA_CLOUD_API_KEY") {
        if !api_key.is_empty() {
            req = req.header("x-ritma-api-key", api_key);
        }
    }
    req = req.header("x-ritma-org-id", org_id);

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target = "utl_http::ritma_cloud",
                "failed to contact ritma_cloud for key governance (key_id={}): {}",
                key_id,
                e,
            );
            return Ok(());
        }
    };

    if !resp.status().is_success() {
        tracing::warn!(
            target = "utl_http::ritma_cloud",
            "ritma_cloud GET /keys/{} returned status {} (allowing signing)",
            key_id,
            resp.status(),
        );
        return Ok(());
    }

    let governance: RitmaCloudKeyGovernance = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target = "utl_http::ritma_cloud",
                "failed to parse key governance response for {}: {}",
                key_id,
                e,
            );
            return Ok(());
        }
    };

    let status_lc = governance.status.to_lowercase();
    if status_lc == "revoked" || status_lc == "compromised" {
        tracing::warn!(
            target = "utl_http::ritma_cloud",
            "refusing to sign with key {} because governance status is {}",
            key_id,
            governance.status,
        );
        return Err(format!(
            "signing key {} is {} according to ritma_cloud governance",
            key_id, governance.status,
        ));
    }

    Ok(())
}

fn summarize_scope(scope: &PackageScope) -> (String, Option<String>, Option<String>) {
    match scope {
        PackageScope::PolicyCommit {
            commit_id,
            framework,
        } => (
            format!("policy_commit:{commit_id}"),
            Some("policy_commit".to_string()),
            framework.clone(),
        ),
        PackageScope::ComplianceBurn { burn_id, framework } => (
            format!("burn:{burn_id}"),
            Some("compliance_burn".to_string()),
            Some(framework.clone()),
        ),
        PackageScope::Incident { incident_id, .. } => (
            format!("incident:{incident_id}"),
            Some("incident".to_string()),
            None,
        ),
        PackageScope::TimeRange {
            time_start,
            time_end,
            framework,
        } => (
            format!("time_range:{time_start}:{time_end}"),
            Some("time_range".to_string()),
            framework.clone(),
        ),
        PackageScope::Custom { description, .. } => (
            format!("custom:{description}"),
            Some("custom".to_string()),
            None,
        ),
    }
}

async fn send_evidence_to_ritma_cloud(
    manifest: EvidencePackageManifest,
) -> Result<(), reqwest::Error> {
    let base = match ritma_cloud_base_url() {
        Some(b) => b,
        None => return Ok(()),
    };
    let org_id = match ritma_cloud_org_id() {
        Some(id) => id,
        None => return Ok(()),
    };

    let node_id = ritma_cloud_node_id();
    let tenant_id = manifest.tenant_id.clone();

    let (scope, report_type, framework) = summarize_scope(&manifest.scope);

    let summary = RitmaCloudEvidenceSummary {
        org_id,
        tenant_id,
        node_id,
        package_id: manifest.package_id.clone(),
        scope,
        report_type,
        framework,
        signed: manifest.security.signature.is_some(),
        created_at: manifest.created_at,
    };

    let url = format!("{}/evidence", base.trim_end_matches('/'));

    reqwest::Client::new()
        .post(url)
        .json(&summary)
        .send()
        .await
        .map(|_| ())
}

#[derive(Serialize)]
struct RitmaCloudSloEvent {
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

async fn send_slo_to_ritma_cloud(
    component: String,
    operation: String,
    outcome: String,
) -> Result<(), reqwest::Error> {
    let base = match ritma_cloud_base_url() {
        Some(b) => b,
        None => return Ok(()),
    };
    let org_id = match ritma_cloud_org_id() {
        Some(id) => id,
        None => return Ok(()),
    };

    let node_id = ritma_cloud_node_id();
    let tenant_id = std::env::var("RITMA_CLOUD_TENANT_ID").ok();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let event = RitmaCloudSloEvent {
        org_id,
        tenant_id,
        node_id,
        component,
        operation,
        outcome,
        count: 1,
        window_start: now,
        window_end: now,
    };

    let url = format!("{}/slo/ingest", base.trim_end_matches('/'));

    reqwest::Client::new()
        .post(url)
        .json(&event)
        .send()
        .await
        .map(|_| ())
}

#[derive(Serialize)]
struct RitmaCloudKeySummary {
    org_id: String,
    node_id: String,
    key_id: String,
    key_hash: String,
    label: Option<String>,
}

#[derive(Deserialize)]
struct RitmaCloudKeyGovernance {
    status: String,
}

async fn send_key_metadata_to_ritma_cloud() -> Result<(), reqwest::Error> {
    let base = match ritma_cloud_base_url() {
        Some(b) => b,
        None => return Ok(()),
    };
    let org_id = match ritma_cloud_org_id() {
        Some(id) => id,
        None => return Ok(()),
    };

    let node_id = ritma_cloud_node_id();
    let key_id = match std::env::var("RITMA_KEY_ID") {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    // Prefer deriving key_hash/label from node keystore when available.
    let (key_hash, label) = if let Ok(ks) = NodeKeystore::from_env() {
        match ks.metadata_for(&key_id) {
            Ok(meta) => (meta.key_hash, meta.label),
            Err(e) => {
                tracing::warn!(
                    target = "utl_http::keystore",
                    "failed to load key metadata from node keystore (key_id={}): {}",
                    key_id,
                    e,
                );
                let key_hash = match std::env::var("RITMA_KEY_HASH") {
                    Ok(v) => v,
                    Err(_) => return Ok(()),
                };
                let label = std::env::var("RITMA_KEY_LABEL").ok();
                (key_hash, label)
            }
        }
    } else {
        let key_hash = match std::env::var("RITMA_KEY_HASH") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let label = std::env::var("RITMA_KEY_LABEL").ok();
        (key_hash, label)
    };

    let summary = RitmaCloudKeySummary {
        org_id,
        node_id,
        key_id,
        key_hash,
        label,
    };

    let url = format!("{}/keys", base.trim_end_matches('/'));

    reqwest::Client::new()
        .post(url)
        .json(&summary)
        .send()
        .await
        .map(|_| ())
}

async fn securitykit_report(
    Query(q): Query<SecurityKitReportQuery>,
) -> Result<Json<SecurityReport>, (axum::http::StatusCode, String)> {
    SecurityReport::generate_for_tenant(q.tenant_id.as_deref())
        .map(Json)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

#[derive(Deserialize, Debug)]
struct DigSearchQuery {
    tenant_id: Option<String>,
    root_id: Option<String>,
    policy_commit_id: Option<String>,
    policy_decision: Option<String>,
    #[serde(default)]
    time_start: Option<u64>,
    #[serde(default)]
    time_end: Option<u64>,
    #[serde(default = "default_limit")]
    limit: usize,
}

#[derive(Serialize)]
struct DigSearchResult {
    entry: DigIndexEntry,
}

async fn search_digs(
    Query(q): Query<DigSearchQuery>,
) -> Result<Json<Vec<DigSearchResult>>, (axum::http::StatusCode, String)> {
    let path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let file = File::open(&path)
        .map_err(|e| bad_request(format!("failed to open dig index {path}: {e}")))?;
    let reader = std::io::BufReader::new(file);

    let mut out = Vec::new();
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("search_digs: failed to read line: {e}");
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let entry: DigIndexEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("search_digs: failed to parse DigIndexEntry: {e}");
                continue;
            }
        };

        if let Some(ref tid) = q.tenant_id {
            if entry.tenant_id.as_deref() != Some(tid.as_str()) {
                continue;
            }
        }
        if let Some(ref rid) = q.root_id {
            if entry.root_id != *rid {
                continue;
            }
        }
        if let Some(ref cid) = q.policy_commit_id {
            if entry.policy_commit_id.as_deref() != Some(cid.as_str()) {
                continue;
            }
        }
        if let Some(ref dec) = q.policy_decision {
            if entry.policy_decision.as_deref() != Some(dec.as_str()) {
                continue;
            }
        }
        if let Some(t0) = q.time_start {
            if entry.time_end < t0 {
                continue;
            }
        }
        if let Some(t1) = q.time_end {
            if entry.time_start > t1 {
                continue;
            }
        }

        out.push(DigSearchResult { entry });
        if out.len() >= q.limit {
            break;
        }
    }

    Ok(Json(out))
}

#[derive(Deserialize, Debug)]
struct ComplianceSearchQuery {
    control_id: Option<String>,
    framework: Option<String>,
    policy_commit_id: Option<String>,
    tenant_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}

#[derive(Serialize)]
struct ComplianceSearchResult {
    record: ControlEvalRecord,
}

// ==== SecurityKit control-plane types ====

#[derive(Deserialize, Debug)]
struct SecurityKitDryRunRequest {
    /// Connectors to validate: e.g. ["kubernetes", "aws", "gcp", "storage"].
    connectors: Vec<String>,
    /// Parameter bundle passed to SecurityKit connectors.
    params: ParamBundle,
}

#[derive(Serialize)]
struct SecurityKitDryRunResponse {
    status: &'static str,
}

#[derive(Deserialize, Debug)]
struct EvidencePackageRequest {
    tenant: String,
    scope_type: String,
    scope_id: String,
    framework: Option<String>,
    #[serde(default)]
    sign: bool,
}

#[derive(Deserialize, Debug)]
struct SecurityKitReportQuery {
    tenant_id: Option<String>,
}

// ==== SecurityKit SLO → Prometheus metrics bridge ====

#[derive(Default)]
struct SloEventVisitor {
    component: Option<String>,
    operation: Option<String>,
    outcome: Option<String>,
}

impl Visit for SloEventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "slo_component" => self.component = Some(value.to_string()),
            "slo_operation" => self.operation = Some(value.to_string()),
            "slo_outcome" => self.outcome = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

struct SecurityKitSloMetricsLayer;

impl<S> Layer<S> for SecurityKitSloMetricsLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        let meta = event.metadata();
        if meta.target() != "security_kit::slo" {
            return;
        }

        let mut visitor = SloEventVisitor::default();
        event.record(&mut visitor);

        let component = match visitor.component {
            Some(c) => c,
            None => return,
        };
        let operation = match visitor.operation {
            Some(o) => o,
            None => return,
        };
        let outcome = visitor.outcome.unwrap_or_else(|| "unknown".to_string());

        let key = format!(
            "ritma_securitykit_slo_events_total{{component=\"{component}\",operation=\"{operation}\",outcome=\"{outcome}\"}} ",
        );
        crate::metrics::inc_labeled_counter(&key);

        let c = component.clone();
        let o = operation.clone();
        let out = outcome.clone();
        tokio::spawn(async move {
            if let Err(e) = send_slo_to_ritma_cloud(c, o, out).await {
                tracing::warn!(
                    target = "utl_http::ritma_cloud",
                    "failed to send SLO telemetry: {}",
                    e
                );
            }
        });
    }
}

async fn search_compliance(
    Query(q): Query<ComplianceSearchQuery>,
) -> Result<Json<Vec<ComplianceSearchResult>>, (axum::http::StatusCode, String)> {
    let path = std::env::var("UTLD_COMPLIANCE_INDEX")
        .unwrap_or_else(|_| "./compliance_index.jsonl".to_string());
    let file = File::open(&path)
        .map_err(|e| bad_request(format!("failed to open compliance index {path}: {e}")))?;
    let reader = std::io::BufReader::new(file);

    let mut out = Vec::new();
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("search_compliance: failed to read line: {e}");
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let rec: ControlEvalRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("search_compliance: failed to parse ControlEvalRecord: {e}");
                continue;
            }
        };

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
        if let Some(ref pid) = q.policy_commit_id {
            if rec.commit_id.as_deref() != Some(pid.as_str()) {
                continue;
            }
        }
        if let Some(ref tid) = q.tenant_id {
            if rec.tenant_id.as_deref() != Some(tid.as_str()) {
                continue;
            }
        }

        out.push(ComplianceSearchResult { record: rec });
        if out.len() >= q.limit {
            break;
        }
    }

    Ok(Json(out))
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

async fn ingest_usage_event(
    State(state): State<AppState>,
    Json(ev): Json<UsageEvent>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // Derive string keys for product and metric using serde's snake_case
    // representation, matching what utld and biz_api already emit.
    let product_val = serde_json::to_value(ev.product)
        .map_err(|e| bad_request(format!("failed to serialize product: {e:?}")))?;
    let metric_val = serde_json::to_value(ev.metric)
        .map_err(|e| bad_request(format!("failed to serialize metric: {e:?}")))?;

    let product = product_val
        .as_str()
        .unwrap_or("<unknown_product>")
        .to_string();
    let metric = metric_val
        .as_str()
        .unwrap_or("<unknown_metric>")
        .to_string();

    let key = (ev.tenant_id.clone(), product, metric);

    {
        let mut totals = state.usage_totals.lock().await;
        *totals.entry(key).or_insert(0) += ev.quantity;
    }

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Serialize)]
struct UsageSummaryEntry {
    tenant_id: String,
    product: String,
    metric: String,
    quantity: u64,
}

async fn usage_summary(State(state): State<AppState>) -> Json<Vec<UsageSummaryEntry>> {
    let totals = state.usage_totals.lock().await;
    let mut entries = Vec::with_capacity(totals.len());
    for ((tenant_id, product, metric), qty) in totals.iter() {
        entries.push(UsageSummaryEntry {
            tenant_id: tenant_id.clone(),
            product: product.clone(),
            metric: metric.clone(),
            quantity: *qty,
        });
    }
    Json(entries)
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

fn init_tracing() {
    let filter = EnvFilter::from_default_env();
    let fmt_layer = tracing_subscriber::fmt::layer();
    let slo_layer = SecurityKitSloMetricsLayer;

    // Configure OTLP exporter for OpenTelemetry (endpoint/env picked up from standard OTEL_* vars).
    let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .expect("failed to create OTLP span exporter");

    let tracer_provider = sdktrace::SdkTracerProvider::builder()
        .with_batch_exporter(otlp_exporter)
        .build();

    global::set_tracer_provider(tracer_provider);
    let tracer = global::tracer("utl_http");

    let otel_layer = OpenTelemetryLayer::new(tracer);

    let subscriber = Registry::default()
        .with(filter)
        .with(slo_layer)
        .with(otel_layer)
        .with(fmt_layer);

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

#[tokio::main]
async fn main() {
    init_tracing();
    let socket = std::env::var("UTLD_SOCKET").unwrap_or_else(|_| "/tmp/utld.sock".to_string());
    let client = Arc::new(UtlClient::new(socket));

    let auth_token = std::env::var("UTLD_API_TOKEN").ok();
    let auth_tenants = load_tenant_tokens();
    let metrics = Arc::new(Metrics::new());
    let usage_totals = Arc::new(Mutex::new(BTreeMap::new()));
    let state = AppState {
        client,
        auth_token,
        auth_tenants,
        metrics,
        usage_totals,
    };

    // Best-effort key metadata telemetry to ritma_cloud on startup.
    tokio::spawn(async {
        if let Err(e) = send_key_metadata_to_ritma_cloud().await {
            tracing::warn!(
                target = "utl_http::ritma_cloud",
                "failed to send key telemetry: {}",
                e
            );
        }
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(readiness))
        .route("/metrics", get(metrics_handler))
        .route("/roots", get(list_roots).post(register_root))
        .route("/transitions", post(record_transition))
        .route("/dig", post(build_dig))
        .route("/entropy", post(build_entropy))
        .route("/usage_events", post(ingest_usage_event))
        .route("/usage_summary", get(usage_summary))
        .route("/search/decisions", get(search_decisions))
        .route("/search/digs", get(search_digs))
        .route("/search/compliance", get(search_compliance))
        .route(
            "/securitykit/connectors/dry_run",
            post(securitykit_connectors_dry_run),
        )
        .route(
            "/securitykit/evidence_package",
            post(securitykit_evidence_package),
        )
        .route("/securitykit/report", get(securitykit_report))
        .with_state(state);

    let addr: SocketAddr = std::env::var("UTLD_HTTP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .expect("invalid UTLD_HTTP_ADDR");

    // Optional HTTPS listener using tokio-rustls + security_os helpers.
    if let Ok(tls_addr_str) = std::env::var("UTL_HTTP_TLS_ADDR") {
        if let Some(cfg) = load_http_mtls_config_from_env() {
            match tls_addr_str.parse::<SocketAddr>() {
                Ok(tls_addr) => {
                    let app_clone = app.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            tls_transport::serve_https_tokio_rustls(tls_addr, cfg, app_clone).await
                        {
                            tracing::error!("HTTPS server error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("invalid UTL_HTTP_TLS_ADDR {}: {}", tls_addr_str, e);
                }
            }
        }
    }

    tracing::info!("utl_http listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn readiness(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // Check if we can reach utld
    match state.client.send(&NodeRequest::ListRoots) {
        Ok(NodeResponse::Roots { .. }) => Ok(Json(serde_json::json!({
            "status": "ready",
            "utld": "connected"
        }))),
        Ok(_) => Ok(Json(serde_json::json!({
            "status": "ready",
            "utld": "connected"
        }))),
        Err(e) => Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!("utld not ready: {e:?}"),
        )),
    }
}

async fn list_roots(
    State(state): State<AppState>,
) -> Result<Json<RootsResponse>, (axum::http::StatusCode, String)> {
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
            format!("unexpected response from utld: {other:?}"),
        )),
    }
}

async fn register_root(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    peer_did: Option<Extension<PeerDid>>,
    Json(mut body): Json<RegisterRootBody>,
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

    // Inject DID from client cert into params for utld (step 7).
    if let Some(Extension(PeerDid(Some(did)))) = peer_did {
        let did_str = did.as_str().to_string();
        body.params
            .entry("actor_did".to_string())
            .or_insert_with(|| did_str.clone());
        body.params.entry("src_did".to_string()).or_insert(did_str);
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
            state
                .metrics
                .transitions_total
                .fetch_add(1, Ordering::Relaxed);
            Ok(Json(serde_json::json!({ "status": "ok" })))
        }
        NodeResponse::Error { message } => {
            state
                .metrics
                .transition_errors_total
                .fetch_add(1, Ordering::Relaxed);
            Err((axum::http::StatusCode::BAD_REQUEST, message))
        }
        other => Err((
            axum::http::StatusCode::BAD_GATEWAY,
            format!("unexpected response from utld: {other:?}"),
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
            state
                .metrics
                .dig_seals_total
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .transitions_total
                .fetch_add(1, Ordering::Relaxed);
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
            format!("unexpected response from utld: {other:?}"),
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

    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");

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
    peer_did: Option<Extension<PeerDid>>,
    Json(mut body): Json<RecordTransitionBody>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // Inject DID from client cert into params for utld (step 7).
    if let Some(Extension(PeerDid(Some(did)))) = peer_did {
        let did_str = did.as_str().to_string();
        body.params
            .entry("actor_did".to_string())
            .or_insert_with(|| did_str.clone());
        body.params.entry("src_did".to_string()).or_insert(did_str);
    }
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
            format!("unexpected response from utld: {other:?}"),
        )),
    }
}

fn parse_hash32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

async fn metrics_handler(State(state): State<AppState>) -> String {
    // Include both Prometheus metrics and legacy counters
    let mut output =
        metrics::encode_metrics().unwrap_or_else(|e| format!("# Error encoding metrics: {e}\n"));

    // Add legacy metrics for backward compatibility
    output.push_str(&format!(
        "\n# Legacy metrics\nritma_transitions_total {}\nritma_transition_errors_total {}\nritma_dig_seals_total {}\n",
        state.metrics.transitions_total.load(Ordering::Relaxed),
        state.metrics.transition_errors_total.load(Ordering::Relaxed),
        state.metrics.dig_seals_total.load(Ordering::Relaxed),
    ));

    output
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
    (
        axum::http::StatusCode::BAD_GATEWAY,
        format!("utld error: {e:?}"),
    )
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

        if let Some(header_tid) = headers.get("x-tenant-id").and_then(|v| v.to_str().ok()) {
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
        let expected_header = format!("Bearer {expected}");
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
    fields.insert(
        "raw_data".to_string(),
        SecValue::String(raw_data.to_string()),
    );

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
            .or_insert_with(|| format!("{max_threat:.3}"));

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
            if lower.contains("' or 1=1")
                || lower.contains(" or 1=1")
                || lower.contains("union select")
            {
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
            usage_totals: Arc::new(Mutex::new(BTreeMap::new())),
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
            usage_totals: Arc::new(Mutex::new(BTreeMap::new())),
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

    #[test]
    fn key_governance_enforcement_env_parsing() {
        std::env::remove_var("RITMA_ENFORCE_KEY_GOVERNANCE");
        assert!(!key_governance_enforcement_enabled());

        std::env::set_var("RITMA_ENFORCE_KEY_GOVERNANCE", "1");
        assert!(key_governance_enforcement_enabled());

        std::env::set_var("RITMA_ENFORCE_KEY_GOVERNANCE", "true");
        assert!(key_governance_enforcement_enabled());

        std::env::set_var("RITMA_ENFORCE_KEY_GOVERNANCE", "false");
        assert!(!key_governance_enforcement_enabled());
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
