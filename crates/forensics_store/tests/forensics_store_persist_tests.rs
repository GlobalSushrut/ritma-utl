use std::fs;
use std::path::Path;

use forensics_store::persist_dig_to_fs;
use tempfile::tempdir;

#[test]
fn persist_dig_to_fs_creates_expected_path_and_content() {
    let dir = tempdir().expect("tempdir");
    std::env::set_var("UTLD_FORENSICS_DIR", dir.path());

    let tenant = Some("tenant-a".to_string());
    let root_id: u128 = 42;
    let file_id: u128 = 7;
    let ts: u64 = 1_700_000_000; // fixed timestamp for deterministic path
    let payload = "{\"ok\":true}";

    let stored_path = persist_dig_to_fs(tenant.as_deref(), root_id, file_id, ts, ts, payload)
        .expect("persist_dig_to_fs");

    let p = Path::new(&stored_path);
    assert!(p.exists(), "persisted file should exist");

    // Path should live under the configured base dir and tenant directory.
    let rel = p.strip_prefix(dir.path()).expect("path under base dir");
    let components: Vec<_> = rel.components().collect();
    assert!(
        components.len() >= 5,
        "expected at least tenant/YYYY/MM/DD/file"
    );

    let filename = components.last().unwrap().as_os_str().to_string_lossy();
    let expected_prefix = format!("root-{}_file-{}", root_id, file_id);
    assert!(
        filename.starts_with(&expected_prefix),
        "filename '{}' should start with '{}'",
        filename,
        expected_prefix
    );

    let contents = fs::read_to_string(&stored_path).expect("read persisted file");
    assert_eq!(contents, payload);
}
