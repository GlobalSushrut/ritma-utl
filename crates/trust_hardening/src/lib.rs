use index_db::IndexDb;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("Continuity broken: gap detected between {0} and {1}")]
    ContinuityGap(i64, i64),

    #[error("Rollback detected: counter {0} < previous {1}")]
    Rollback(i64, i64),

    #[error("Time drift detected: {0}s")]
    TimeDrift(i64),

    #[error("Chain hash mismatch")]
    ChainHashMismatch,

    #[error("Database error: {0}")]
    DbError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    pub namespace_id: String,
    pub last_counter: i64,
    pub last_timestamp: i64,
    pub last_hash: String,
}

pub struct TrustValidator {
    db: IndexDb,
}

impl TrustValidator {
    pub fn new(db: IndexDb) -> Self {
        Self { db }
    }

    pub fn validate_continuity(
        &self,
        namespace_id: &str,
        new_counter: i64,
        _new_timestamp: i64,
    ) -> Result<(), TrustError> {
        let last = self
            .db
            .get_last_receipt(namespace_id)
            .map_err(|e| TrustError::DbError(e.to_string()))?;

        if let Some((_, _, last_counter)) = last {
            if new_counter <= last_counter {
                return Err(TrustError::Rollback(new_counter, last_counter));
            }

            if new_counter != last_counter + 1 {
                return Err(TrustError::ContinuityGap(last_counter, new_counter));
            }
        }

        Ok(())
    }

    pub fn compute_chain_hash(
        &self,
        namespace_id: &str,
        prev_hash: &str,
        counter: i64,
        public_inputs_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(namespace_id.as_bytes());
        hasher.update(prev_hash.as_bytes());
        hasher.update(counter.to_le_bytes());
        hasher.update(public_inputs_hash.as_bytes());
        hex::encode(hasher.finalize())
    }
}
