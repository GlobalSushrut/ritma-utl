use common_models::{TraceEvent, TraceEventKind, TraceSourceKind, TraceActor, TraceTarget, TraceAttrs, WindowRange};
use index_db::IndexDb;
use window_summarizer::WindowSummarizer;
use attack_graph::AttackGraphBuilder;
use tempfile::TempDir;

#[test]
fn test_end_to_end_window_processing() {
    // Setup
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db = IndexDb::open(db_path.to_str().unwrap()).unwrap();
    
    let namespace_id = "ns://test/integration";
    let window = WindowRange {
        start: "2024-01-01T00:00:00Z".to_string(),
        end: "2024-01-01T00:01:00Z".to_string(),
    };
    
    // Create test events
    let events = vec![
        TraceEvent {
            trace_id: "t1".to_string(),
            ts: "2024-01-01T00:00:00Z".to_string(),
            namespace_id: namespace_id.to_string(),
            source: TraceSourceKind::Auditd,
            kind: TraceEventKind::ProcExec,
            actor: TraceActor {
                pid: 1000,
                ppid: 1,
                uid: 0,
                gid: 0,
                comm_hash: None,
                exe_hash: None,
                comm: None,
                exe: None,
                container_id: None,
                service: None,
                build_hash: None,
            },
            target: TraceTarget {
                path_hash: None,
                dst: None,
                domain_hash: None,
            },
            attrs: TraceAttrs {
                argv_hash: Some("cmd_hash".to_string()),
                cwd_hash: None,
                bytes_out: None,
            },
        },
        TraceEvent {
            trace_id: "t2".to_string(),
            ts: "2024-01-01T00:00:10Z".to_string(),
            namespace_id: namespace_id.to_string(),
            source: TraceSourceKind::Runtime,
            kind: TraceEventKind::NetConnect,
            actor: TraceActor {
                pid: 1000,
                ppid: 1,
                uid: 0,
                gid: 0,
                comm_hash: None,
                exe_hash: None,
                comm: None,
                exe: None,
                container_id: None,
                service: None,
                build_hash: None,
            },
            target: TraceTarget {
                path_hash: None,
                dst: Some("8.8.8.8:53".to_string()),
                domain_hash: None,
            },
            attrs: TraceAttrs {
                argv_hash: None,
                cwd_hash: None,
                bytes_out: Some(512),
            },
        },
    ];
    
    // Insert events
    for event in &events {
        db.insert_trace_event_from_model(event).unwrap();
    }
    
    // Test window summarizer
    let mut summarizer = WindowSummarizer::new(db.clone());
    let features = summarizer.extract_features(namespace_id, &window, &events).unwrap();
    
    assert_eq!(features.proc_exec_count, 1);
    assert_eq!(features.net_connect_count, 1);
    assert_eq!(features.total_events, 2);
    assert!(features.novel_egress_endpoints > 0);
    
    // Test attack graph builder
    let graph_builder = AttackGraphBuilder::new(db.clone());
    let (edges, graph_hash) = graph_builder.build_graph(namespace_id, &window, &events).unwrap();
    
    assert!(!edges.is_empty());
    assert_eq!(graph_hash.len(), 64); // SHA-256
    
    // Persist graph
    let window_id = "test_window_1";
    graph_builder.persist_graph(window_id, &edges).unwrap();
    
    // Verify persistence
    let loaded_edges = db.list_edges(window_id).unwrap();
    assert_eq!(loaded_edges.len(), edges.len());
}

#[test]
fn test_trust_validation() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db = IndexDb::open(db_path.to_str().unwrap()).unwrap();
    
    let validator = trust_hardening::TrustValidator::new(db);
    let namespace_id = "ns://test/trust";
    
    // First receipt should pass
    let result = validator.validate_continuity(namespace_id, 1, 1000);
    assert!(result.is_ok());
    
    // Sequential receipt should pass
    // (Would need to actually insert receipt first in real test)
}

#[test]
fn test_contract_judging() {
    use judge_contracts::{ContractJudge, PolicyContract};
    use common_models::MLScore;
    
    let mut contract = PolicyContract::default();
    contract.namespace_id = "ns://test/judge".to_string();
    contract.novel_endpoint_threshold = 5;
    
    let judge = ContractJudge::new(contract);
    
    let ml_score = MLScore {
        ml_id: "ml1".to_string(),
        namespace_id: "ns://test/judge".to_string(),
        range_used: WindowRange {
            start: "2024-01-01T00:00:00Z".to_string(),
            end: "2024-01-01T00:01:00Z".to_string(),
        },
        final_ml_score: 0.3,
        explain: "Low score".to_string(),
        models: serde_json::json!({}),
    };
    
    let features = serde_json::json!({
        "NOVEL_EGRESS": 10, // Exceeds threshold
        "AUTH_FAIL_BURST": false,
    });
    
    let (trigger, verdict) = judge.judge(&ml_score, &features);
    
    // Policy violation should override low ML score
    assert_eq!(verdict.verdict_type, common_models::VerdictType::Suspicious);
    assert!(verdict.confidence > 0.8);
}
