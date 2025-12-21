use std::fs;

use dig_index::{append_index_entry, DigIndexEntry};
use tempfile::tempdir;

#[test]
fn append_index_entry_writes_json_line() {
    let dir = tempdir().expect("tempdir");
    let index_path = dir.path().join("dig_index.jsonl");
    let db_path = dir.path().join("dig_index.sqlite");

    std::env::set_var("UTLD_DIG_INDEX", &index_path);
    std::env::set_var("UTLD_DIG_INDEX_DB", &db_path);

    let entry = DigIndexEntry {
        file_id: "file-1".to_string(),
        root_id: "root-1".to_string(),
        tenant_id: Some("tenant-a".to_string()),
        time_start: 100,
        time_end: 200,
        record_count: 3,
        merkle_root: "abcd".to_string(),
        snark_root: None,
        policy_name: Some("policy".to_string()),
        policy_version: Some("1.0.0".to_string()),
        policy_decision: Some("allow".to_string()),
        storage_path: Some("/tmp/path".to_string()),
        policy_commit_id: None,
        prev_index_hash: None,
        svc_commits: vec!["svc_123".to_string()],
        infra_version_id: Some("infra_456".to_string()),
        camera_frames: vec!["frame_789".to_string()],
        actor_dids: vec!["did:ritma:user:alice".to_string()],
        compliance_framework: Some("SOC2".to_string()),
        compliance_burn_id: Some("burn_abc".to_string()),
        file_hash: Some("hash_def".to_string()),
        compression: None,
        encryption: None,
        signature: None,
        schema_version: 2,
    };

    append_index_entry(&entry).expect("append_index_entry");

    let content = fs::read_to_string(&index_path).expect("read index file");
    let mut lines = content.lines();
    let line = lines.next().expect("at least one line");
    assert!(lines.next().is_none(), "expected exactly one line");

    let decoded: DigIndexEntry = serde_json::from_str(line).expect("decode DigIndexEntry");
    assert_eq!(decoded.file_id, entry.file_id);
    assert_eq!(decoded.root_id, entry.root_id);
    assert_eq!(decoded.tenant_id, entry.tenant_id);
    assert_eq!(decoded.record_count, entry.record_count);
}
