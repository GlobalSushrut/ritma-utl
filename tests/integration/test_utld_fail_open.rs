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

fn send_utld_request(sock: &PathBuf) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(sock)?;

    let req = json!({
        "type": "list_roots",
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
fn utld_fail_open_when_bar_unavailable() -> Result<()> {
    let tmpdir = TempDir::new()?;
    let utld_sock = tmpdir.path().join("utld.sock");

    // Expect utld binary to have been built already in debug mode.
    let utld_bin = workspace_root().join("target/debug/utld");
    if !utld_bin.exists() {
        println!(
            "Skipping utld_fail_open_when_bar_unavailable: {} not found (run: cargo build -p utld --features bar_governance)",
            utld_bin.display()
        );
        return Ok(());
    }

    // Start utld with BAR governance enabled in enforce mode, but do NOT start
    // bar_daemon. BAR client calls should fail, and utld must fail-open back to
    // local behavior (list_roots should still respond, even if empty).
    let mut utld_child = Command::new(&utld_bin)
        .env("UTLD_SOCKET", &utld_sock)
        .env("UTLD_BAR_GOVERNANCE_MODE", "enforce")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    assert!(
        wait_for_socket(&utld_sock, 5)?,
        "utld socket did not appear"
    );

    let resp = send_utld_request(&utld_sock)?;

    // We expect a valid NodeResponse::Roots or NodeResponse::Error but not a
    // crash. BAR failures must not prevent utld from answering.
    assert!(
        resp.get("status").is_some(),
        "response must contain status field"
    );

    let _ = utld_child.kill();
    let _ = std::fs::remove_file(&utld_sock);

    Ok(())
}
