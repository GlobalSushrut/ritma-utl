use serde::{Deserialize, Serialize};
use thiserror::Error;

use common_models::{NamespaceId, Receipt};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptId(pub String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TimeRange {
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Debug, Error)]
pub enum UtlClientError {
    #[error("io error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, UtlClientError>;

/// Minimal UTL client interface aligned with the executable architecture spec.
///
/// Concrete implementations (e.g. Unix-socket clients) can live in other
/// crates; this trait defines the expected behavior and shapes.
pub trait UtlClient {
    /// Append a receipt to the UTL chain for its namespace, returning a
    /// ReceiptId that can be used for later verification and queries.
    fn append_receipt(&self, receipt: &Receipt) -> Result<ReceiptId>;

    /// Verify the receipt chain up to and including the given ReceiptId.
    fn verify_chain(&self, receipt_id: &ReceiptId) -> Result<bool>;

    /// Query receipts for a namespace and optional time range.
    fn query_receipts(
        &self,
        namespace: &NamespaceId,
        time_range: Option<TimeRange>,
    ) -> Result<Vec<Receipt>>;

    /// Export an evidence bundle (e.g., for an incident) over a namespace and
    /// time range. The concrete bundle format is left to the implementation.
    fn export_bundle(
        &self,
        namespace: &NamespaceId,
        time_range: TimeRange,
    ) -> Result<serde_json::Value>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopUtlClient;

    impl UtlClient for NoopUtlClient {
        fn append_receipt(&self, receipt: &Receipt) -> Result<ReceiptId> {
            Ok(ReceiptId(receipt.receipt_id.clone()))
        }

        fn verify_chain(&self, _receipt_id: &ReceiptId) -> Result<bool> {
            Ok(true)
        }

        fn query_receipts(
            &self,
            _namespace: &NamespaceId,
            _time_range: Option<TimeRange>,
        ) -> Result<Vec<Receipt>> {
            Ok(Vec::new())
        }

        fn export_bundle(
            &self,
            _namespace: &NamespaceId,
            _time_range: TimeRange,
        ) -> Result<serde_json::Value> {
            Ok(serde_json::json!({"status": "ok"}))
        }
    }

    #[test]
    fn utl_client_trait_compiles() {
        let client = NoopUtlClient;
        let receipt = Receipt {
            receipt_id: "r_1".to_string(),
            namespace_id: "ns://acme/prod/payments/api".to_string(),
            prev_hash: "0".to_string(),
            event_hash: "evh".to_string(),
            verdict_hash: "verh".to_string(),
            contract_hash: "contract".to_string(),
            config_hash: "cfg".to_string(),
            ts: "t1".to_string(),
            utl_chain_hash: "chain".to_string(),
        };
        let rid = client.append_receipt(&receipt).expect("append_receipt");
        assert_eq!(rid.0, "r_1");
        assert!(client.verify_chain(&rid).unwrap());
        let ns = NamespaceId::parse("ns://acme/prod/payments/api").unwrap();
        let _ = client
            .query_receipts(&ns, None)
            .expect("query_receipts");
        let _ = client
            .export_bundle(&ns, TimeRange { not_before: 0, not_after: 0 })
            .expect("export_bundle");
    }
}
