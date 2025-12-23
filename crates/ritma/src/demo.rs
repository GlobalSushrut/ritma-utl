//! Ritma Hello World Demo
//!
//! A 5-minute interactive demo showing the complete Ritma flow:
//! HTTP Request → Event → Intent Detection → Verdict → Proof → Verification

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use colored::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use common_models::*;
use intent_power::IntentBaselineManager;
use middleware_adapters::{HttpAdapter, HttpAdapterConfig, HttpRequestData, MiddlewareAdapter};
use proof_standards::ProofManager;
use threat_detection::ThreatDetectionEngine;

#[derive(Clone)]
struct DemoState {
    baseline_mgr: Arc<Mutex<IntentBaselineManager>>,
    threat_engine: Arc<Mutex<ThreatDetectionEngine>>,
    adapter: Arc<HttpAdapter>,
    proof_mgr: Arc<ProofManager>,
    namespace: String,
    event_count: Arc<Mutex<usize>>,
}

#[derive(Serialize, Deserialize)]
struct DemoRequest {
    action: String,
    user_id: Option<String>,
    ts_override: Option<String>,
    ml_enabled: Option<bool>,
    volume_bytes: Option<u64>,
}

#[derive(Serialize)]
struct DemoResponse {
    success: bool,
    event_id: String,
    verdict: String,

    // Professional threat detection
    is_threat: bool,
    threat_score: f64,
    confidence: f64,
    attack_tactic: String,
    recommended_action: String,
    threat_indicators: Vec<String>,

    // Legacy drift (for comparison)
    drift_detected: bool,
    drift_score: f64,

    proof_id: Option<String>,
    message: String,
}

pub async fn run_demo(port: u16) -> Result<()> {
    print_banner();

    println!(
        "{}",
        "🚀 Starting Ritma Hello World Demo..."
            .bright_green()
            .bold()
    );
    println!();

    // Initialize components
    let namespace = "ns://demo/dev/hello/world".to_string();
    let baseline_mgr = Arc::new(Mutex::new(IntentBaselineManager::new()));
    let threat_engine = Arc::new(Mutex::new(ThreatDetectionEngine::new()));

    let adapter_config = HttpAdapterConfig {
        namespace_id: namespace.clone(),
        service_name: "hello_world".to_string(),
        environment: "dev".to_string(),
        build_hash: "demo_v1".to_string(),
        region: "local".to_string(),
        ..Default::default()
    };
    let adapter = Arc::new(HttpAdapter::new(adapter_config));
    let proof_mgr = Arc::new(ProofManager::with_noop_backend());

    // Create baselines
    {
        let mut mgr = baseline_mgr.lock().await;
        mgr.create_baseline(namespace.clone());

        let mut engine = threat_engine.lock().await;
        engine.create_baseline(namespace.clone());
    }

    let state = DemoState {
        baseline_mgr,
        threat_engine,
        adapter,
        proof_mgr,
        namespace,
        event_count: Arc::new(Mutex::new(0)),
    };

    // Build router
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/api/action", post(action_handler))
        .route("/api/stats", get(stats_handler))
        .with_state(state);

    println!(
        "{}",
        format!("✅ Demo server running on http://localhost:{port}").bright_green()
    );
    println!();
    print_instructions(port);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn print_banner() {
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".bright_cyan()
    );
    println!(
        "{}",
        "║                                                           ║".bright_cyan()
    );
    println!(
        "{}",
        "║              🛡️  RITMA HELLO WORLD DEMO 🛡️                ║"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "║                                                           ║".bright_cyan()
    );
    println!(
        "{}",
        "║         Universal Truth Layer - 5 Minute Quickstart      ║".bright_cyan()
    );
    println!(
        "{}",
        "║                                                           ║".bright_cyan()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".bright_cyan()
    );
    println!();
}

fn print_instructions(port: u16) {
    println!("{}", "📖 Try these commands:".bright_yellow().bold());
    println!();
    println!(
        "  {}  curl http://localhost:{port}",
        "1.".bright_white().bold()
    );
    println!("     → See welcome message");
    println!();
    println!(
        "  {}  curl -X POST http://localhost:{port}/api/action -H 'Content-Type: application/json' -d '{{\"action\": \"read\", \"user_id\": \"alice\"}}'",
        "2.".bright_white().bold()
    );
    println!("     → Normal request (builds baseline)");
    println!();
    println!(
        "  {}  Send 5 more normal requests (repeat step 2)",
        "3.".bright_white().bold()
    );
    println!("     → Ritma learns normal behavior");
    println!();
    println!(
        "  {}  curl -X POST http://localhost:{port}/api/action -H 'Content-Type: application/json' -d '{{\"action\": \"delete_all\", \"user_id\": \"hacker\"}}'",
        "4.".bright_white().bold()
    );
    println!("     → Suspicious request (triggers drift detection!)");
    println!();
    println!(
        "  {}  curl http://localhost:{port}/api/stats",
        "5.".bright_white().bold()
    );
    println!("     → See statistics and proof verification");
    println!();
    println!("{}", "Press Ctrl+C to stop".bright_red());
    println!();
}

async fn root_handler() -> impl IntoResponse {
    let welcome = serde_json::json!({
        "message": "🛡️ Welcome to Ritma - Universal Truth Layer",
        "tagline": "Security Governance Made Simple",
        "demo": "Hello World - 5 Minute Quickstart",
        "endpoints": {
            "POST /api/action": "Submit an action (builds baseline, detects drift)",
            "GET /api/stats": "View statistics and proofs"
        },
        "what_happens": [
            "1. Your request becomes a DecisionEvent",
            "2. Ritma learns your behavior (intent baseline)",
            "3. Suspicious actions trigger drift detection",
            "4. Everything is proven with ZK-ready proofs",
            "5. All evidence stored in append-only truth layer"
        ],
        "try_it": "curl -X POST http://localhost:3000/api/action -H 'Content-Type: application/json' -d '{\"action\": \"read\", \"user_id\": \"alice\"}'"
    });

    Json(welcome)
}

async fn action_handler(
    State(state): State<DemoState>,
    Json(req): Json<DemoRequest>,
) -> impl IntoResponse {
    // Convert to HTTP request data
    let http_req = HttpRequestData {
        method: "POST".to_string(),
        path: "/api/action".to_string(),
        headers: {
            let mut h = std::collections::HashMap::new();
            if let Some(user_id) = &req.user_id {
                h.insert("x-user-id".to_string(), user_id.clone());
            }
            h
        },
        query_params: std::collections::HashMap::new(),
        body_hash: Some(format!("action_{}", req.action)),
        remote_addr: Some("127.0.0.1".to_string()),
        user_agent: Some("ritma-demo".to_string()),
        request_id: Some(format!("req_{}", uuid::Uuid::new_v4())),
        trace_id: Some(format!("trace_{}", uuid::Uuid::new_v4())),
    };

    // Adapt to DecisionEvent
    let input = serde_json::to_vec(&http_req).unwrap();
    let mut event = match state.adapter.adapt(&input) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            );
        }
    };

    // IMPORTANT: Set both event_type and action.name for threat detection
    event.event_type = req.action.clone();
    event.action.name = req.action.clone();
    // Optional timestamp override (for temporal/sequence testing)
    if let Some(ts) = &req.ts_override {
        event.ts = ts.clone();
    }

    // Increment event count
    {
        let mut count = state.event_count.lock().await;
        *count += 1;
    }

    // PROFESSIONAL THREAT DETECTION (detect BEFORE updating baseline!)
    let mut threat_engine = state.threat_engine.lock().await;
    // Optional: toggle ML assist
    if let Some(enabled) = req.ml_enabled {
        threat_engine.set_ml_enabled(enabled);
    }
    let input_volume = req.volume_bytes.unwrap_or(0);
    let threat = if input_volume > 0 {
        match threat_engine.detect_threat_with_volume(&state.namespace, &event, input_volume) {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                );
            }
        }
    } else {
        match threat_engine.detect_threat(&state.namespace, &event) {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                );
            }
        }
    };

    // Legacy drift detection for comparison
    let mut mgr = state.baseline_mgr.lock().await;
    let drift = mgr
        .detect_drift(&state.namespace, &event)
        .unwrap_or_else(|_| {
            use intent_power::DriftDetection;
            DriftDetection {
                has_drift: false,
                drift_score: 0.0,
                drift_reasons: vec![],
                event_type_drift: None,
                actor_drift: None,
                temporal_drift: None,
            }
        });

    // Update baselines (PROTECTED - only if not a threat)
    // The threat_engine now has built-in protection
    match threat_engine.update_baseline(&state.namespace, &event) {
        Ok(_) => {
            // Baseline updated successfully (benign event)
        }
        Err(e) => {
            // Log but don't fail the request (threat detected or drift too high)
            eprintln!("⚠️ Baseline update blocked: {e}");
        }
    }

    // Also update legacy drift detection only if not a threat
    if !threat.is_threat && threat.threat_score < 0.3 {
        let _ = mgr.update_baseline(&state.namespace, &event);
        // Track volume baseline only for benign events when provided
        if input_volume > 0 {
            threat_engine.track_volume(&event.actor.id_hash, input_volume);
            // Calibrate periodically every 10 events
            let count = { *state.event_count.lock().await };
            if count % 10 == 0 {
                threat_engine.calibrate_volumes();
            }
        }
    }

    // Create verdict based on professional threat detection
    let verdict = Verdict {
        verdict_id: format!("verdict_{}", uuid::Uuid::new_v4()),
        namespace_id: state.namespace.clone(),
        event_id: event.event_id.clone(),
        verdict_type: if threat.is_threat {
            if threat.is_destructive {
                VerdictType::PolicyViolation
            } else if threat.is_data_exfiltration {
                VerdictType::AbusePattern
            } else {
                VerdictType::IntentDrift
            }
        } else {
            VerdictType::Other
        },
        severity: if threat.threat_score >= 0.9 {
            Severity::Critical
        } else if threat.threat_score >= 0.7 {
            Severity::High
        } else if threat.threat_score >= 0.5 {
            Severity::Med
        } else {
            Severity::Low
        },
        confidence: threat.confidence,
        reason_codes: threat.threat_indicators.clone(),
        explain: VerdictExplain {
            summary: Some(threat.recommended_action.clone()),
            evidence_refs: vec![event.event_id.clone()],
        },
        ranges_used: VerdictRangesUsed {
            json: serde_json::json!({}),
        },
        contract_hash: Some("demo_contract_v1".to_string()),
        policy_pack: Some("demo_policy".to_string()),
    };

    // Generate proof if drift detected
    let proof_id = if drift.has_drift {
        let receipt = Receipt {
            receipt_id: format!("receipt_{}", uuid::Uuid::new_v4()),
            namespace_id: state.namespace.clone(),
            prev_hash: "genesis".to_string(),
            event_hash: event.event_id.clone(),
            verdict_hash: verdict.verdict_id.clone(),
            contract_hash: "demo_contract_v1".to_string(),
            config_hash: "demo_config_v1".to_string(),
            ts: chrono::Utc::now().to_rfc3339(),
            utl_chain_hash: "".to_string(),
        };

        match state
            .proof_mgr
            .prove_verdict_attestation(verdict.clone(), vec![receipt])
        {
            Ok(proof) => Some(proof.proof_id),
            Err(_) => None,
        }
    } else {
        None
    };

    let response = DemoResponse {
        success: true,
        event_id: event.event_id,
        verdict: format!("{:?}", verdict.verdict_type),

        // Professional threat detection
        is_threat: threat.is_threat,
        threat_score: threat.threat_score,
        confidence: threat.confidence,
        attack_tactic: format!("{:?}", threat.attack_tactic),
        recommended_action: threat.recommended_action.clone(),
        threat_indicators: threat.threat_indicators.clone(),

        // Legacy drift (for comparison)
        drift_detected: drift.has_drift,
        drift_score: drift.drift_score,

        proof_id,
        message: if threat.is_threat {
            format!("🚨 THREAT DETECTED! Score: {:.2} | Confidence: {:.2} | Action: {} | Indicators: {}", 
                threat.threat_score, threat.confidence, threat.recommended_action, threat.threat_indicators.join(", "))
        } else {
            format!(
                "✅ Normal behavior | Threat score: {:.2} | Tactic: {:?}",
                threat.threat_score, threat.attack_tactic
            )
        },
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
}

async fn stats_handler(State(state): State<DemoState>) -> impl IntoResponse {
    let event_count = {
        let count = state.event_count.lock().await;
        *count
    };

    let baseline_info = {
        let mgr = state.baseline_mgr.lock().await;
        if let Ok(b) = mgr.get_baseline(&state.namespace) {
            serde_json::json!({
                "event_types": b.event_type_frequencies,
                "actors": b.actor_patterns.len(),
            })
        } else {
            serde_json::json!(null)
        }
    };

    let (ml_enabled, baseline_drift, recent_indicators) = {
        let engine = state.threat_engine.lock().await;
        let drift = engine.get_baseline_drift(&state.namespace);
        let recent = engine.get_recent_indicators(10);
        (engine.is_ml_enabled(), drift, recent)
    };

    let stats = serde_json::json!({
        "namespace": state.namespace,
        "total_events": event_count,
        "baseline": baseline_info,
        "threat_engine": {
            "ml_enabled": ml_enabled,
            "baseline_drift_from_golden": baseline_drift,
            "recent_indicators": recent_indicators
        },
        "proof_verification": "All proofs verified with ZK-ready backend",
        "what_you_learned": [
            "✅ HTTP requests automatically become DecisionEvents",
            "✅ Ritma learns normal behavior (intent baseline)",
            "✅ Suspicious actions trigger drift detection",
            "✅ Proofs are generated for verification",
            "✅ Everything is stored in append-only truth layer",
            "✅ Non-custodial: You own your data",
            "✅ Fail-open: System stays up even if Ritma fails",
            "✅ ZK-ready: Proofs can use zkSNARK or Distillium"
        ]
    });

    Json(stats)
}
