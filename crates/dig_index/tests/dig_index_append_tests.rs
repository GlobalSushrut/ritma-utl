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
        prev_index_hash: None,
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
