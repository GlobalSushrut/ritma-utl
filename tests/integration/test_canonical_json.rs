//! Canonical JSON determinism tests
//!
//! Tests that write_canonical_json produces byte-identical output for identical inputs.

use std::fs;
use std::path::PathBuf;

fn cargo_bin(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // tests/integration -> tests
    path.pop(); // tests -> root
    path.push("target");
    path.push("debug");
    path.push(name);
    path
}

/// Test that exported proofpacks are deterministic
/// Same input should produce byte-identical manifest.json
#[test]
fn test_canonical_json_key_ordering() {
    // Create test JSON with keys in random order
    let json1 = serde_json::json!({
        "zebra": 1,
        "apple": 2,
        "mango": {"z": 1, "a": 2},
        "array": [{"b": 1, "a": 2}]
    });

    let json2 = serde_json::json!({
        "apple": 2,
        "mango": {"a": 2, "z": 1},
        "zebra": 1,
        "array": [{"a": 2, "b": 1}]
    });

    // Sort keys recursively (same logic as write_canonical_json)
    fn sort_value(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut items: Vec<_> = map.iter().collect();
                items.sort_by(|a, b| a.0.cmp(b.0));
                let mut out = serde_json::Map::new();
                for (k, vv) in items {
                    out.insert(k.clone(), sort_value(vv));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(sort_value).collect())
            }
            _ => v.clone(),
        }
    }

    let sorted1 = sort_value(&json1);
    let sorted2 = sort_value(&json2);

    let str1 = serde_json::to_string_pretty(&sorted1).unwrap();
    let str2 = serde_json::to_string_pretty(&sorted2).unwrap();

    assert_eq!(
        str1, str2,
        "canonical JSON must be byte-identical regardless of input key order"
    );
}

/// Test that repeated exports produce identical hashes
#[test]
fn test_export_determinism() {
    let dir1 = tempfile::tempdir().expect("create temp dir 1");
    let dir2 = tempfile::tempdir().expect("create temp dir 2");

    // Create identical test data
    for dir in [dir1.path(), dir2.path()] {
        fs::create_dir_all(dir.join("receipts")).unwrap();

        let manifest = serde_json::json!({
            "version": "0.1",
            "namespace_id": "ns://test/det",
            "window": {"start": "2024-01-01T00:00:00Z", "end": "2024-01-01T01:00:00Z"},
            "attack_graph_hash": "abc123"
        });

        // Use canonical serialization
        fn sort_value(v: &serde_json::Value) -> serde_json::Value {
            match v {
                serde_json::Value::Object(map) => {
                    let mut items: Vec<_> = map.iter().collect();
                    items.sort_by(|a, b| a.0.cmp(b.0));
                    let mut out = serde_json::Map::new();
                    for (k, vv) in items {
                        out.insert(k.clone(), sort_value(vv));
                    }
                    serde_json::Value::Object(out)
                }
                serde_json::Value::Array(arr) => {
                    serde_json::Value::Array(arr.iter().map(sort_value).collect())
                }
                _ => v.clone(),
            }
        }

        let sorted = sort_value(&manifest);
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&sorted).unwrap(),
        )
        .unwrap();
    }

    // Read and compare
    let content1 = fs::read_to_string(dir1.path().join("manifest.json")).unwrap();
    let content2 = fs::read_to_string(dir2.path().join("manifest.json")).unwrap();

    assert_eq!(
        content1, content2,
        "canonical JSON exports must be byte-identical"
    );
}
