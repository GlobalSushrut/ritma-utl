use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use bar_core::{ObservedEvent, PolicyVerdict};
use serde_json::Value;
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum BarClientError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("daemon error: {0}")]
    DaemonError(String),

    #[error("protocol error: {0}")]
    ProtocolError(String),
}

pub struct BarClient {
    socket_path: String,
}

impl BarClient {
    pub fn new<S: Into<String>>(socket_path: S) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Construct a client using the same default/env logic as bar_daemon.
    /// BAR_SOCKET env var is honored, falling back to /tmp/bar_daemon.sock.
    pub fn from_env() -> Self {
        let socket_path =
            std::env::var("BAR_SOCKET").unwrap_or_else(|_| "/tmp/bar_daemon.sock".to_string());
        Self { socket_path }
    }

    pub fn evaluate(&self, event: &ObservedEvent) -> Result<PolicyVerdict, BarClientError> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        // Short, conservative timeouts so callers are not left hanging if the
        // daemon is overloaded or misbehaving.
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let json = serde_json::to_string(event)?;
        debug!("sending ObservedEvent to BAR: {}", json);
        writeln!(stream, "{json}")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            return Err(BarClientError::ProtocolError(
                "unexpected EOF while waiting for PolicyVerdict".to_string(),
            ));
        }

        let trimmed = line.trim();
        debug!("received response from BAR: {}", trimmed);

        // First parse as generic JSON so we can surface daemon error responses.
        let v: Value = serde_json::from_str(trimmed)?;
        if let Some(err) = v.get("error") {
            return Err(BarClientError::DaemonError(err.to_string()));
        }

        let verdict: PolicyVerdict = serde_json::from_value(v)?;
        Ok(verdict)
    }
}
