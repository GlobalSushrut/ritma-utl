//! Manifest signature integration tests
//!
//! Tests for ProofPack manifest signing and offline verification.

use sha2::Digest;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn cargo_bin(name: &str) -> PathBuf {
    // Try to find the binary in target/debug or target/release
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // tests/integration -> tests
    path.pop(); // tests -> root
    
    // Check debug first, then release
    let debug_path = path.join("target/debug").join(name);
    if debug_path.exists() {
        return debug_path;
    }
    
    let release_path = path.join("target/release").join(name);
    if release_path.exists() {
        return release_path;
    }
    
    // Return debug path as default (will fail with clear error)
    debug_path
}

/// Skip test if ritma binary is not built
fn skip_if_no_binary() -> bool {
    let bin = cargo_bin("ritma");
    if !bin.exists() {
        eprintln!("Skipping test: ritma binary not found at {bin:?}");
        true
    } else {
        false
    }
}

/// Create a minimal valid proofpack structure for testing
fn create_test_proofpack(dir: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("receipts"))?;

    let manifest = serde_json::json!({
        "version": "0.1",
        "namespace_id": "ns://test/sig",
        "window": {"start": "2024-01-01T00:00:00Z", "end": "2024-01-01T01:00:00Z"},
        "attack_graph_hash": "deadbeef1234"
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    let pub_inputs = serde_json::json!({"test": true});
    fs::write(
        dir.join("receipts/public_inputs.json"),
        serde_json::to_string_pretty(&pub_inputs)?,
    )?;

    // Calculate actual hashes
    let manifest_data = fs::read(dir.join("manifest.json"))?;
    let manifest_sha = hex::encode(sha2::Digest::finalize(
        sha2::Sha256::new().chain_update(&manifest_data),
    ));

    let receipts_data = fs::read(dir.join("receipts/public_inputs.json"))?;
    let receipts_sha = hex::encode(sha2::Digest::finalize(
        sha2::Sha256::new().chain_update(&receipts_data),
    ));

    let proofpack = serde_json::json!({
        "version": "0.1",
        "namespace_id": "ns://test/sig",
        "inputs": {
            "manifest_sha256": manifest_sha,
            "receipts_sha256": receipts_sha,
            "vk_id": "test_vk",
            "public_inputs_hash": "abc123"
        },
        "range": {"window": {"start": "2024-01-01T00:00:00Z", "end": "2024-01-01T01:00:00Z"}}
    });
    fs::write(
        dir.join("proofpack.json"),
        serde_json::to_string_pretty(&proofpack)?,
    )?;

    Ok(())
}

#[test]
fn test_verify_unsigned_proofpack_passes() {
    if skip_if_no_binary() { return; }
    let dir = tempfile::tempdir().expect("create temp dir");
    create_test_proofpack(dir.path()).expect("create proofpack");

    let output = Command::new(cargo_bin("ritma"))
        .args(["verify-proof", "--path"])
        .arg(dir.path())
        .arg("--json")
        .output()
        .expect("run ritma verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");

    assert_eq!(result["status"], "ok", "unsigned pack should verify ok");
    assert_eq!(result["signature"]["present"], false);
    assert_eq!(result["signature"]["ok"], true);
}

#[test]
fn test_signed_proofpack_verifies() {
    if skip_if_no_binary() { return; }
    use sha2::Digest;

    let dir = tempfile::tempdir().expect("create temp dir");
    create_test_proofpack(dir.path()).expect("create proofpack");

    // Generate ed25519 keypair and sign
    let secret_bytes: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let manifest_data = fs::read(dir.path().join("manifest.json")).expect("read manifest");
    let manifest_sha = hex::encode(sha2::Sha256::digest(&manifest_data));

    use ed25519_dalek::Signer;
    let sig = signing_key.sign(manifest_sha.as_bytes());

    let sig_file = serde_json::json!({
        "version": "ritma-manifest-sig@0.1",
        "manifest_sha256": manifest_sha,
        "signature_type": "ed25519",
        "signature_hex": hex::encode(sig.to_bytes()),
        "signer_id": "test_signer",
        "public_key_hex": hex::encode(verifying_key.to_bytes()),
        "signed_at": 1704067200
    });
    fs::write(
        dir.path().join("manifest.sig"),
        serde_json::to_string_pretty(&sig_file).unwrap(),
    )
    .expect("write sig");

    let output = Command::new(cargo_bin("ritma"))
        .args(["verify-proof", "--path"])
        .arg(dir.path())
        .arg("--json")
        .output()
        .expect("run ritma verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");

    assert_eq!(result["status"], "ok", "signed pack should verify ok");
    assert_eq!(result["signature"]["present"], true);
    assert_eq!(result["signature"]["ok"], true);
}

#[test]
fn test_tampered_manifest_fails_signature() {
    if skip_if_no_binary() { return; }
    use sha2::Digest;

    let dir = tempfile::tempdir().expect("create temp dir");
    create_test_proofpack(dir.path()).expect("create proofpack");

    // Generate ed25519 keypair and sign
    let secret_bytes: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let manifest_data = fs::read(dir.path().join("manifest.json")).expect("read manifest");
    let manifest_sha = hex::encode(sha2::Sha256::digest(&manifest_data));

    use ed25519_dalek::Signer;
    let sig = signing_key.sign(manifest_sha.as_bytes());

    let sig_file = serde_json::json!({
        "version": "ritma-manifest-sig@0.1",
        "manifest_sha256": manifest_sha,
        "signature_type": "ed25519",
        "signature_hex": hex::encode(sig.to_bytes()),
        "signer_id": "test_signer",
        "public_key_hex": hex::encode(verifying_key.to_bytes()),
        "signed_at": 1704067200
    });
    fs::write(
        dir.path().join("manifest.sig"),
        serde_json::to_string_pretty(&sig_file).unwrap(),
    )
    .expect("write sig");

    // Now tamper with the manifest
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("manifest.json")).unwrap())
            .unwrap();
    manifest["tampered"] = serde_json::json!(true);
    fs::write(
        dir.path().join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write tampered");

    // Also update proofpack.json with new manifest hash so manifest check passes
    let new_manifest_data = fs::read(dir.path().join("manifest.json")).expect("read manifest");
    let new_manifest_sha = hex::encode(sha2::Sha256::digest(&new_manifest_data));
    let mut proofpack: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("proofpack.json")).unwrap())
            .unwrap();
    proofpack["inputs"]["manifest_sha256"] = serde_json::json!(new_manifest_sha);
    fs::write(
        dir.path().join("proofpack.json"),
        serde_json::to_string_pretty(&proofpack).unwrap(),
    )
    .expect("write proofpack");

    let output = Command::new(cargo_bin("ritma"))
        .args(["verify-proof", "--path"])
        .arg(dir.path())
        .arg("--json")
        .output()
        .expect("run ritma verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");

    assert_eq!(result["status"], "mismatch", "tampered pack should fail");
    assert_eq!(result["signature"]["present"], true);
    assert_eq!(result["signature"]["ok"], false);
}

#[test]
fn test_wrong_signature_fails() {
    if skip_if_no_binary() { return; }
    use sha2::Digest;

    let dir = tempfile::tempdir().expect("create temp dir");
    create_test_proofpack(dir.path()).expect("create proofpack");

    // Generate ed25519 keypair
    let secret_bytes: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let manifest_data = fs::read(dir.path().join("manifest.json")).expect("read manifest");
    let manifest_sha = hex::encode(sha2::Sha256::digest(&manifest_data));

    // Sign something else (wrong data)
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(b"wrong_data");

    let sig_file = serde_json::json!({
        "version": "ritma-manifest-sig@0.1",
        "manifest_sha256": manifest_sha,
        "signature_type": "ed25519",
        "signature_hex": hex::encode(sig.to_bytes()),
        "signer_id": "test_signer",
        "public_key_hex": hex::encode(verifying_key.to_bytes()),
        "signed_at": 1704067200
    });
    fs::write(
        dir.path().join("manifest.sig"),
        serde_json::to_string_pretty(&sig_file).unwrap(),
    )
    .expect("write sig");

    let output = Command::new(cargo_bin("ritma"))
        .args(["verify-proof", "--path"])
        .arg(dir.path())
        .arg("--json")
        .output()
        .expect("run ritma verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout).expect("parse json");

    assert_eq!(result["status"], "mismatch", "wrong signature should fail");
    assert_eq!(result["signature"]["present"], true);
    assert_eq!(result["signature"]["ok"], false);
}
