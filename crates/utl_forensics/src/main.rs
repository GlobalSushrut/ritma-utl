use std::io::BufRead;
use std::net::SocketAddr;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use dig_index::DigIndexEntry;
use dig_mem::DigFile;
use serde::Serialize;
use tokio::net::TcpListener;

#[derive(Serialize)]
struct ForensicDigEntry {
    file_id: String,
    root_id: String,
    tenant_id: Option<String>,
    time_start: u64,
    time_end: u64,
    record_count: usize,
    merkle_root: String,
    policy_name: Option<String>,
    policy_version: Option<String>,
    policy_decision: Option<String>,
    path: Option<String>,
}

#[derive(serde::Deserialize)]
struct ListDigsParams {
    tenant: Option<String>,
    root_id: Option<String>,
    limit: Option<usize>,
    show_path: Option<bool>,
    policy_decision: Option<String>,
    since: Option<u64>,
    until: Option<u64>,
}

#[derive(serde::Deserialize)]
struct GetDigParams {
    root_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct EvidenceParams {
    root_id: Option<String>,
}

#[derive(Serialize)]
struct ForensicDigResponse {
    entry: ForensicDigEntry,
    dig: DigFile,
}

#[derive(Clone)]
struct AppState {
    api_token: Option<String>,
}

#[derive(Serialize)]
struct EvidenceBundle {
    // Core identity
    tenant_id: Option<String>,
    root_id: String,
    file_id: String,

    // Time and integrity
    time_start: u64,
    time_end: u64,
    record_count: usize,
    merkle_root: String,

    // Policy context
    policy_name: Option<String>,
    policy_version: Option<String>,
    policy_decision: Option<String>,

    // Storage
    path: Option<String>,

    // Full dig payload
    dig: DigFile,
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = std::env::var("UTL_FORENSICS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9100".to_string())
        .parse()
        .expect("invalid UTL_FORENSICS_ADDR");

    let state = AppState {
        api_token: std::env::var("UTL_FORENSICS_TOKEN").ok(),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/digs", get(list_digs))
        .route("/digs/:file_id", get(get_dig))
        .route("/evidence/:file_id", get(get_evidence))
        .with_state(state);

    println!("utl_forensics listening on {addr}");
    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind forensics listener");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn list_digs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListDigsParams>,
) -> Result<Json<Vec<ForensicDigEntry>>, (axum::http::StatusCode, String)> {
    check_auth(&state, &headers)?;
    let index_path =
        std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let file = std::fs::File::open(&index_path).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to open dig index {index_path}: {e}"),
        )
    })?;

    let reader = std::io::BufReader::new(file);
    let mut results = Vec::new();
    let mut printed = 0usize;
    let limit = params.limit.unwrap_or(50);
    let show_path = params.show_path.unwrap_or(false);

    for line_result in reader.lines() {
        let line = line_result.map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("error reading dig index {index_path}: {e}"),
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: DigIndexEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping malformed index entry: {e}");
                continue;
            }
        };

        if let Some(t) = params.tenant.as_deref() {
            if entry.tenant_id.as_deref() != Some(t) {
                continue;
            }
        }

        if let Some(r) = params.root_id.as_deref() {
            if entry.root_id.as_str() != r {
                continue;
            }
        }

        if let Some(dec) = params.policy_decision.as_deref() {
            if entry.policy_decision.as_deref() != Some(dec) {
                continue;
            }
        }

        if let Some(since) = params.since {
            if entry.time_end < since {
                continue;
            }
        }

        if let Some(until) = params.until {
            if entry.time_start > until {
                continue;
            }
        }

        let path = if show_path {
            resolve_dig_path(&entry)
        } else {
            None
        };

        results.push(ForensicDigEntry {
            file_id: entry.file_id,
            root_id: entry.root_id,
            tenant_id: entry.tenant_id,
            time_start: entry.time_start,
            time_end: entry.time_end,
            record_count: entry.record_count,
            merkle_root: entry.merkle_root,
            policy_name: entry.policy_name,
            policy_version: entry.policy_version,
            policy_decision: entry.policy_decision,
            path,
        });

        printed += 1;
        if printed >= limit {
            break;
        }
    }

    Ok(Json(results))
}

async fn get_dig(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Query(params): Query<GetDigParams>,
) -> Result<Json<ForensicDigResponse>, (axum::http::StatusCode, String)> {
    check_auth(&state, &headers)?;
    let index_path =
        std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let file = std::fs::File::open(&index_path).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to open dig index {index_path}: {e}"),
        )
    })?;

    let reader = std::io::BufReader::new(file);
    let mut matched: Option<DigIndexEntry> = None;

    for line_result in reader.lines() {
        let line = line_result.map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("error reading dig index {index_path}: {e}"),
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: DigIndexEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping malformed index entry: {e}");
                continue;
            }
        };

        if entry.file_id != file_id {
            continue;
        }

        if let Some(r) = params.root_id.as_deref() {
            if entry.root_id.as_str() != r {
                continue;
            }
        }

        matched = Some(entry);
        break;
    }

    let entry = matched.ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            format!("no dig index entry found for file_id={file_id}"),
        )
    })?;

    let path = resolve_dig_path(&entry).ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            format!(
                "could not resolve DigFile path for file_id={} root_id={}",
                entry.file_id, entry.root_id
            ),
        )
    })?;

    let content = std::fs::read_to_string(&path).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to read dig file {path}: {e}"),
        )
    })?;
    let dig: DigFile = serde_json::from_str(&content).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to parse dig file {path}: {e}"),
        )
    })?;

    let resp = ForensicDigResponse {
        entry: ForensicDigEntry {
            file_id: entry.file_id,
            root_id: entry.root_id,
            tenant_id: entry.tenant_id,
            time_start: entry.time_start,
            time_end: entry.time_end,
            record_count: entry.record_count,
            merkle_root: entry.merkle_root,
            policy_name: entry.policy_name,
            policy_version: entry.policy_version,
            policy_decision: entry.policy_decision,
            path: Some(path),
        },
        dig,
    };

    Ok(Json(resp))
}

async fn get_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Query(params): Query<EvidenceParams>,
) -> Result<Json<EvidenceBundle>, (axum::http::StatusCode, String)> {
    check_auth(&state, &headers)?;
    let index_path =
        std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let file = std::fs::File::open(&index_path).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to open dig index {index_path}: {e}"),
        )
    })?;

    let reader = std::io::BufReader::new(file);
    let mut matched: Option<DigIndexEntry> = None;

    for line_result in reader.lines() {
        let line = line_result.map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("error reading dig index {index_path}: {e}"),
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: DigIndexEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping malformed index entry: {e}");
                continue;
            }
        };

        if entry.file_id != file_id {
            continue;
        }

        if let Some(r) = params.root_id.as_deref() {
            if entry.root_id.as_str() != r {
                continue;
            }
        }

        matched = Some(entry);
        break;
    }

    let entry = matched.ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            format!("no dig index entry found for file_id={file_id}"),
        )
    })?;

    let path = resolve_dig_path(&entry);

    let dig = if let Some(ref p) = path {
        let content = std::fs::read_to_string(p).map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read dig file {p}: {e}"),
            )
        })?;
        serde_json::from_str::<DigFile>(&content).map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to parse dig file {p}: {e}"),
            )
        })?
    } else {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            format!(
                "could not resolve DigFile path for file_id={} root_id={}",
                entry.file_id, entry.root_id
            ),
        ));
    };

    let bundle = EvidenceBundle {
        tenant_id: entry.tenant_id,
        root_id: entry.root_id,
        file_id: entry.file_id,
        time_start: entry.time_start,
        time_end: entry.time_end,
        record_count: entry.record_count,
        merkle_root: entry.merkle_root,
        policy_name: entry.policy_name,
        policy_version: entry.policy_version,
        policy_decision: entry.policy_decision,
        path,
        dig,
    };

    Ok(Json(bundle))
}

fn resolve_dig_path(entry: &DigIndexEntry) -> Option<String> {
    let base_dir = std::env::var("UTLD_DIG_DIR").unwrap_or_else(|_| "./dig".to_string());
    let pattern = format!("root-{}_file-{}_", entry.root_id, entry.file_id);

    if let Ok(dir_entries) = std::fs::read_dir(&base_dir) {
        for entry_fs in dir_entries.flatten() {
            if let Ok(name) = entry_fs.file_name().into_string() {
                if name.starts_with(&pattern) && name.ends_with(".dig.json") {
                    return Some(format!("{base_dir}/{name}"));
                }
            }
        }
    }

    None
}

fn check_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (axum::http::StatusCode, String)> {
    // If no token is configured, allow all (useful for dev).
    let Some(expected) = state.api_token.as_ref() else {
        return Ok(());
    };

    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let expected_header = format!("Bearer {expected}");
    if auth != expected_header {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            "missing or invalid Authorization bearer token".to_string(),
        ));
    }

    Ok(())
}
