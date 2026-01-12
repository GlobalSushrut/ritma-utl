//! Full pipeline integration test
//!
//! This test demonstrates the complete flow from HTTP request ingestion
//! through intent detection, proof generation, and persistence.

use common_models::*;
use index_db::IndexDb;
use intent_power::IntentBaselineManager;
use middleware_adapters::{HttpAdapter, HttpAdapterConfig, HttpRequestData, MiddlewareAdapter};
use proof_standards::ProofManager;
use std::collections::HashMap;

#[test]
fn full_pipeline_http_to_proof() {
    // Setup: Create in-memory database (migrate is called in open)
    let db = IndexDb::open(":memory:").expect("open db");

    // Step 1: Configure HTTP adapter
    let adapter_config = HttpAdapterConfig {
        namespace_id: "ns://acme/prod/payments/api".to_string(),
        service_name: "payments_api".to_string(),
        environment: "prod".to_string(),
        build_hash: "build_v1.2.3".to_string(),
        region: "us-east-1".to_string(),
        ..Default::default()
    };
    let adapter = HttpAdapter::new(adapter_config);

    // Step 2: Simulate HTTP request
    let http_request = HttpRequestData {
        method: "POST".to_string(),
        path: "/api/payments/charge".to_string(),
        headers: {
            let mut h = HashMap::new();
            h.insert("x-user-id".to_string(), "user_12345".to_string());
            h.insert("authorization".to_string(), "Bearer token123".to_string());
            h
        },
        query_params: HashMap::new(),
        body_hash: Some("body_hash_abc".to_string()),
        remote_addr: Some("192.168.1.100".to_string()),
        user_agent: Some("PaymentApp/1.0".to_string()),
        request_id: Some("req_xyz789".to_string()),
        trace_id: Some("trace_abc123".to_string()),
    };

    // Step 3: Convert to DecisionEvent
    let input = serde_json::to_vec(&http_request).expect("serialize");
    let event = adapter.adapt(&input).expect("adapt");

    // Verify event structure
    assert_eq!(event.namespace_id, "ns://acme/prod/payments/api");
    assert_eq!(event.event_type, "HTTP_POST");
    assert_eq!(event.env_stamp.service, "payments_api");
    assert_eq!(event.context.request_id, Some("req_xyz789".to_string()));

    // Step 4: Persist event to IndexDB using helper
    db.insert_event_from_decision(&event).expect("insert event");

    // Step 5: Create a verdict manually (MinimalPipeline expects different input)
    let verdict = Verdict {
        verdict_id: format!("verdict_{}", uuid::Uuid::new_v4()),
        namespace_id: event.namespace_id.clone(),
        event_id: event.event_id.clone(),
        verdict_type: VerdictType::PolicyViolation,
        severity: Severity::Med,
        confidence: 0.85,
        reason_codes: vec!["NORMAL_OPERATION".to_string()],
        explain: VerdictExplain {
            summary: Some("Payment request processed".to_string()),
            evidence_refs: vec![],
        },
        ranges_used: VerdictRangesUsed {
            json: serde_json::json!({}),
        },
        contract_hash: Some("contract_hash_v1".to_string()),
        policy_pack: Some("payments_policy_v1".to_string()),
    };

    // Step 6: Persist verdict using helper
    db.insert_verdict_from_model(&verdict)
        .expect("insert verdict");

    // Step 7: Create receipt
    let receipt = Receipt {
        receipt_id: "receipt_001".to_string(),
        namespace_id: event.namespace_id.clone(),
        prev_hash: "genesis".to_string(),
        event_hash: event.event_id.clone(),
        verdict_hash: verdict.verdict_id.clone(),
        contract_hash: "contract_hash_v1".to_string(),
        config_hash: "config_hash_v1".to_string(),
        ts: chrono::Utc::now().to_rfc3339(),
        utl_chain_hash: "".to_string(),
    };

    let chain_hash = receipt.compute_chain_hash();
    let mut receipt_with_hash = receipt.clone();
    receipt_with_hash.utl_chain_hash = chain_hash;

    // Step 8: Intent baseline and drift detection
    let mut baseline_mgr = IntentBaselineManager::new();
    baseline_mgr.create_baseline(event.namespace_id.clone());

    // Update baseline with normal behavior
    baseline_mgr
        .update_baseline(&event.namespace_id, &event)
        .expect("update baseline");

    // Create a suspicious event (different event type, different actor)
    let mut suspicious_event = event.clone();
    suspicious_event.event_id = "evt_suspicious".to_string();
    suspicious_event.event_type = "HTTP_DELETE".to_string();
    suspicious_event.actor.id_hash = "unknown_actor_hash".to_string();

    // Detect drift
    let drift = baseline_mgr
        .detect_drift(&event.namespace_id, &suspicious_event)
        .expect("detect drift");

    // Should detect drift (unknown event type + unknown actor = 0.7 > 0.5 threshold)
    assert!(drift.has_drift, "Should detect drift for suspicious event");
    assert!(
        drift.drift_score > 0.5,
        "Drift score should exceed threshold"
    );

    // Step 9: Generate proof for verdict attestation
    let proof_mgr = ProofManager::with_noop_backend();
    let proof = proof_mgr
        .prove_verdict_attestation(verdict.clone(), vec![receipt_with_hash.clone()])
        .expect("generate proof");

    // Verify proof
    assert_eq!(proof.namespace_id, event.namespace_id);
    assert_eq!(proof.proof_type, "noop");

    let is_valid = proof_mgr.verify(&proof).expect("verify proof");
    assert!(is_valid, "Proof should be valid");

    // Step 10: Persist proof metadata (requires status parameter)
    db.insert_proof_from_pack(&proof, "generated")
        .expect("insert proof");

    // Step 11: Query events back using events_since
    let events = db
        .events_since(&event.namespace_id, 0)
        .expect("query events");
    assert_eq!(events.len(), 1, "Should have 1 event");

    // Verify end-to-end data integrity
    assert_eq!(events[0].event_id, event.event_id);
    assert_eq!(events[0].namespace_id, event.namespace_id);
}

#[test]
fn multiple_events_baseline_learning() {
    // Setup (migrate is called in open)
    let db = IndexDb::open(":memory:").expect("open db");

    let adapter_config = HttpAdapterConfig {
        namespace_id: "ns://acme/prod/api/svc".to_string(),
        service_name: "api_svc".to_string(),
        environment: "prod".to_string(),
        build_hash: "build_v1".to_string(),
        region: "us-west-2".to_string(),
        ..Default::default()
    };
    let adapter = HttpAdapter::new(adapter_config);

    // Create baseline manager
    let mut baseline_mgr = IntentBaselineManager::new();
    baseline_mgr.create_baseline("ns://acme/prod/api/svc".to_string());

    // Simulate 10 normal GET requests from the same user
    for i in 0..10 {
        let http_request = HttpRequestData {
            method: "GET".to_string(),
            path: format!("/api/users/{i}"),
            headers: {
                let mut h = HashMap::new();
                h.insert("x-user-id".to_string(), "user_normal".to_string());
                h
            },
            query_params: HashMap::new(),
            body_hash: None,
            remote_addr: Some("10.0.0.1".to_string()),
            user_agent: Some("NormalApp/1.0".to_string()),
            request_id: Some(format!("req_{i}")),
            trace_id: Some(format!("trace_{i}")),
        };

        let input = serde_json::to_vec(&http_request).expect("serialize");
        let event = adapter.adapt(&input).expect("adapt");

        // Update baseline
        baseline_mgr
            .update_baseline(&event.namespace_id, &event)
            .expect("update baseline");

        // Persist using helper
        db.insert_event_from_decision(&event).expect("insert event");
    }

    // Now simulate an anomalous request (POST from different user)
    let anomalous_request = HttpRequestData {
        method: "POST".to_string(),
        path: "/api/admin/delete_all".to_string(),
        headers: {
            let mut h = HashMap::new();
            h.insert("x-user-id".to_string(), "user_suspicious".to_string());
            h
        },
        query_params: HashMap::new(),
        body_hash: Some("dangerous_payload".to_string()),
        remote_addr: Some("192.168.1.1".to_string()),
        user_agent: Some("curl/7.68.0".to_string()),
        request_id: Some("req_anomaly".to_string()),
        trace_id: Some("trace_anomaly".to_string()),
    };

    let input = serde_json::to_vec(&anomalous_request).expect("serialize");
    let anomalous_event = adapter.adapt(&input).expect("adapt");

    // Detect drift
    let drift = baseline_mgr
        .detect_drift(&anomalous_event.namespace_id, &anomalous_event)
        .expect("detect drift");

    // Should detect drift
    assert!(drift.has_drift, "Should detect anomalous behavior");
    assert!(!drift.drift_reasons.is_empty(), "Should have drift reasons");

    // Verify we have 10 normal events in DB
    let events = db
        .events_since("ns://acme/prod/api/svc", 0)
        .expect("query events");
    assert_eq!(events.len(), 10, "Should have 10 normal events");
}
