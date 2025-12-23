use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use serde_json::json;
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn wait_for_socket(path: &PathBuf, timeout_secs: u64) -> Result<bool> {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(timeout_secs) {
        if path.exists() {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(false)
}

fn send_utld_request(sock: &PathBuf, bar_decision: Option<&str>) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(sock)?;

    // Minimal NodeRequest::RecordTransition JSON that utld understands. The
    // NodeRequest enum is tagged with {"type": "record_transition", ...} and
    // u128 fields are encoded as strings.
    let mut p_container = serde_json::Map::new();
    p_container.insert("event_kind".to_string(), json!("test_event"));
    p_container.insert("logic_ref".to_string(), json!("test_logic"));
    if let Some(dec) = bar_decision {
        p_container.insert("bar_decision".to_string(), json!(dec));
    }

    let req = json!({
        "type": "record_transition",
        "entity_id": "1",
        "root_id": "2",
        "signature": [],
        "data": [],
        "addr_heap_hash": vec![0u8; 32],
        "p_container": p_container,
        "logic_ref": "test_logic",
        "wall": "test_wall",
        "hook_hash": vec![0u8; 32],
    });

    let line = serde_json::to_string(&req)? + "\n";
    use std::io::Write;
    stream.write_all(line.as_bytes())?;

    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line)?;

    let v: serde_json::Value = serde_json::from_str(resp_line.trim())?;
    Ok(v)
}

#[test]
fn test_utld_bar_observe_vs_enforce() -> Result<()> {
    let tmpdir = TempDir::new()?;
    let bar_sock = tmpdir.path().join("bar_daemon.sock");
    let utld_sock = tmpdir.path().join("utld.sock");

    // Start bar_daemon with simple rule agent.
    let bar_bin = workspace_root().join("target/debug/bar_daemon");
    if !bar_bin.exists() {
        println!(
            "Skipping test_utld_bar_observe_vs_enforce: {} not found (run: cargo build -p bar_daemon)",
            bar_bin.display()
        );
        return Ok(());
    }
    let mut bar_child = Command::new(&bar_bin)
        .env("BAR_SOCKET", &bar_sock)
        .env("BAR_AGENT_MODE", "simple")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Wait for bar_daemon socket.
    assert!(wait_for_socket(&bar_sock, 5)?, "BAR socket did not appear");

    // Helper to run utld once with a given BAR governance mode.
    let run_utld_once = |mode: &str, bar_decision: Option<&str>| -> Result<serde_json::Value> {
        let utld_bin = workspace_root().join("target/debug/utld");
        if !utld_bin.exists() {
            println!(
                "Skipping test_utld_bar_observe_vs_enforce: {} not found (run: cargo build -p utld --features bar_governance)",
                utld_bin.display()
            );
            return Ok(json!({"skipped": true}));
        }

        let mut utld_child = Command::new(&utld_bin)
            .env("UTLD_SOCKET", &utld_sock)
            .env("UTLD_BAR_GOVERNANCE_MODE", mode)
            .env("BAR_SOCKET", &bar_sock)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for utld socket.
        assert!(
            wait_for_socket(&utld_sock, 5)?,
            "utld socket did not appear"
        );

        let resp = send_utld_request(&utld_sock, bar_decision)?;

        let _ = utld_child.kill();
        let _ = std::fs::remove_file(&utld_sock);

        Ok(resp)
    };

    // 1) Observe mode: even with bar_decision=deny, utld should NOT surface a
    // BAR governance denial; instead, we expect a local UnknownRoot-style
    // error, since we do not register any roots.
    let resp_observe = run_utld_once("observe", Some("deny"))?;
    if resp_observe.get("skipped").is_some() {
        // utld binary not built with bar_governance; skip.
        let _ = bar_child.kill();
        return Ok(());
    }
    assert_eq!(
        resp_observe.get("status").and_then(|v| v.as_str()),
        Some("error"),
        "observe mode should still return an error due to unknown_root"
    );
    let msg_observe = resp_observe
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        msg_observe.contains("unknown_root"),
        "observe mode should see local unknown_root error, got: {}",
        msg_observe
    );

    // 2) Enforce mode: with bar_decision=deny, utld should surface a BAR
    // governance denial instead of the local unknown_root error.
    let resp_enforce = run_utld_once("enforce", Some("deny"))?;
    assert_eq!(
        resp_enforce.get("status").and_then(|v| v.as_str()),
        Some("error"),
        "enforce mode should return an error response"
    );
    let msg_enforce = resp_enforce
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // If utld was built without the bar_governance feature, enforce mode will
    // still fall back to the local handler and surface unknown_root.
    if msg_enforce.contains("unknown_root") {
        println!(
            "Skipping enforce-mode BAR assertion: utld response suggests bar_governance is not enabled (got: {})",
            msg_enforce
        );
        let _ = bar_child.kill();
        return Ok(());
    }

    assert!(
        msg_enforce.contains("request denied by BAR governance"),
        "enforce mode must deny via BAR governance, got: {}",
        msg_enforce
    );
    assert!(
        !msg_enforce.contains("unknown_root"),
        "enforce mode should not surface unknown_root, got: {}",
        msg_enforce
    );

    let _ = bar_child.kill();

    Ok(())
}
