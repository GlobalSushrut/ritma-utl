use std::path::PathBuf;
use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use bar_client::BarClient;
use bar_core::{ObservedEvent, VerdictDecision};
use serde_json::json;
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    // tests/integration/Cargo.toml is in this directory; workspace root is two levels up.
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn test_bar_daemon_roundtrip_deny_and_allow() -> Result<()> {
    let tmpdir = TempDir::new()?;
    let sock_path = tmpdir.path().join("bar_daemon.sock");

    // Expect bar_daemon to have been built already in debug mode.
    let bin_path = workspace_root().join("target/debug/bar_daemon");
    if !bin_path.exists() {
        println!(
            "Skipping test_bar_daemon_roundtrip_deny_and_allow: {} not found (run: cargo build -p bar_daemon)",
            bin_path.display()
        );
        return Ok(());
    }

    // Spawn bar_daemon with the simple rule agent.
    let mut child = Command::new(&bin_path)
        .env("BAR_SOCKET", &sock_path)
        .env("BAR_AGENT_MODE", "simple")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Give the daemon a moment to bind the socket.
    thread::sleep(Duration::from_secs(2));

    let client = BarClient::new(sock_path.to_string_lossy().to_string());

    // Event that should be denied.
    let deny_event = ObservedEvent {
        namespace_id: "default".to_string(),
        kind: "test".to_string(),
        entity_id: None,
        properties: json!({
            "bar_decision": "deny",
        })
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect(),
    };

    let verdict = client.evaluate(&deny_event)?;
    assert!(matches!(verdict.decision, VerdictDecision::Deny));

    // Event that should be allowed.
    let allow_event = ObservedEvent {
        namespace_id: "default".to_string(),
        kind: "test".to_string(),
        entity_id: None,
        properties: json!({
            "bar_decision": "allow",
        })
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect(),
    };

    let verdict2 = client.evaluate(&allow_event)?;
    assert!(matches!(verdict2.decision, VerdictDecision::Allow));

    // Best-effort shutdown.
    let _ = child.kill();

    Ok(())
}
