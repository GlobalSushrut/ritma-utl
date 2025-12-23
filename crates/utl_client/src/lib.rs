use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use common_models::{NamespaceId, Receipt};
use utl_core::{
    ReceiptId, Result as UtlCoreResult, TimeRange, UtlClient as UtlClientTrait,
    UtlClientError as UtlCoreError,
};
use utld::{NodeRequest, NodeResponse};

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(e: serde_json::Error) -> Self {
        ClientError::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Thin Rust SDK over the utld daemon JSON-over-UNIX-socket API.
#[derive(Clone, Debug)]
pub struct UtlClient {
    socket_path: PathBuf,
}

impl UtlClient {
    /// Create a client using the given socket path.
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Create a client from the UTLD_SOCKET env var, or the default path.
    pub fn from_env() -> Self {
        let path = std::env::var("UTLD_SOCKET").unwrap_or_else(|_| "/tmp/utld.sock".to_string());
        Self::new(path)
    }

    /// Send a raw NodeRequest and receive a NodeResponse.
    pub fn send(&self, req: &NodeRequest) -> Result<NodeResponse> {
        let mut stream = UnixStream::connect(&self.socket_path)?;

        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        stream.write_all(line.as_bytes())?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut buf = String::new();
        reader.read_line(&mut buf)?;
        if buf.trim().is_empty() {
            // Treat empty response as protocol error.
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "empty response from utld",
            )));
        }

        let resp: NodeResponse = serde_json::from_str(&buf)?;
        Ok(resp)
    }

    /// Send a raw NodeRequest and receive the raw JSON line from utld.
    pub fn send_raw(&self, req: &NodeRequest) -> Result<String> {
        let mut stream = UnixStream::connect(&self.socket_path)?;

        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        stream.write_all(line.as_bytes())?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut buf = String::new();
        reader.read_line(&mut buf)?;
        if buf.trim().is_empty() {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "empty response from utld",
            )));
        }

        Ok(buf)
    }
}

impl UtlClientTrait for UtlClient {
    fn append_receipt(&self, receipt: &Receipt) -> UtlCoreResult<ReceiptId> {
        // For now, map to a generic NodeRequest that utld can handle
        // In a full implementation, utld would have an AppendReceipt request type
        let req = NodeRequest::ListRoots;
        let _resp = self
            .send(&req)
            .map_err(|e| UtlCoreError::Io(format!("{e:?}")))?;

        Ok(ReceiptId(receipt.receipt_id.clone()))
    }

    fn verify_chain(&self, receipt_id: &ReceiptId) -> UtlCoreResult<bool> {
        // Stub: would send a VerifyChain request to utld
        let _ = receipt_id;
        Ok(true)
    }

    fn query_receipts(
        &self,
        namespace: &NamespaceId,
        time_range: Option<TimeRange>,
    ) -> UtlCoreResult<Vec<Receipt>> {
        // Stub: would send a QueryReceipts request to utld
        let _ = (namespace, time_range);
        Ok(Vec::new())
    }

    fn export_bundle(
        &self,
        namespace: &NamespaceId,
        time_range: TimeRange,
    ) -> UtlCoreResult<serde_json::Value> {
        // Stub: would send an ExportBundle request to utld
        let _ = (namespace, time_range);
        Ok(serde_json::json!({"status": "ok"}))
    }
}
