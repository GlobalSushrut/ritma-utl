use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bar_core::{BarAgent, NoopBarAgent, ObservedEvent, PolicyVerdict, SimpleRuleBarAgent};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    let filter = EnvFilter::from_default_env();
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn handle_client(stream: UnixStream, agent: Arc<dyn BarAgent>) {
    // Best-effort short timeouts so misbehaving clients do not hang
    // connections indefinitely.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let peer = stream
        .peer_addr()
        .map(|addr| format!("{addr:?}"))
        .unwrap_or_else(|_| "unknown".to_string());

    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            error!("failed to clone BAR client stream {}: {}", peer, e);
            return;
        }
    };

    let mut reader = std::io::BufReader::new(reader_stream);
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(e) => {
                error!("error reading from client {}: {}", peer, e);
                break;
            }
        };

        if bytes == 0 {
            // EOF
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: ObservedEvent = match serde_json::from_str(trimmed) {
            Ok(ev) => ev,
            Err(e) => {
                let err_resp = serde_json::json!({
                    "error": format!("invalid_observed_event: {}", e),
                });
                if let Err(werr) = writeln!(writer, "{err_resp}") {
                    error!("failed to write error response to {}: {}", peer, werr);
                    break;
                }
                continue;
            }
        };

        let verdict: PolicyVerdict = agent.evaluate(&event);

        if let Err(e) = writeln!(writer, "{}", serde_json::to_string(&verdict).unwrap()) {
            error!("failed to write verdict to {}: {}", peer, e);
            break;
        }
    }
}

fn main() -> std::io::Result<()> {
    init_tracing();

    // Use secure socket location, not world-writable /tmp
    let socket_path =
        std::env::var("BAR_SOCKET").unwrap_or_else(|_| "/run/ritma/bar_daemon.sock".to_string());
    
    // Ensure socket directory exists with proper permissions
    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        std::fs::create_dir_all(parent).ok();
    }

    if Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    // Set secure socket permissions - only owner can read/write
    if let Ok(meta) = std::fs::metadata(&socket_path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);  // Owner read/write only
        if let Err(e) = std::fs::set_permissions(&socket_path, perms) {
            error!("failed to set permissions on {}: {}", socket_path, e);
        }
    }

    info!("bar_daemon listening on {}", socket_path);

    let agent_mode = std::env::var("BAR_AGENT_MODE").unwrap_or_else(|_| "noop".to_string());
    let agent: Arc<dyn BarAgent> = match agent_mode.to_lowercase().as_str() {
        "simple" | "simple_rule" => Arc::new(SimpleRuleBarAgent),
        _ => Arc::new(NoopBarAgent),
    };

    for stream_res in listener.incoming() {
        match stream_res {
            Ok(stream) => {
                let agent_clone = Arc::clone(&agent);
                thread::spawn(move || {
                    handle_client(stream, agent_clone);
                });
            }
            Err(e) => {
                error!("error accepting BAR client: {}", e);
            }
        }
    }

    Ok(())
}
