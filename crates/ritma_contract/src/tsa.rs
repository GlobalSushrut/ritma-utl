//! RFC 3161 Time-Stamp Authority (TSA) integration for court-admissible evidence timestamping.
//!
//! Per spec §409-421: External timestamping proves evidence existed at a specific time.
//!
//! Usage:
//! 1. Set RITMA_TSA_URL=https://freetsa.org/tsr (or other TSA endpoint)
//! 2. Call `request_timestamp(hash)` to get a timestamp token
//! 3. Store token in custody_log.tsa_token or proofpack

use sha2::{Digest, Sha256};

/// TSA configuration from environment
#[derive(Debug, Clone)]
pub struct TsaConfig {
    pub url: String,
    pub hash_alg: String,
    pub timeout_secs: u64,
}

impl TsaConfig {
    /// Load TSA config from environment variables.
    /// Returns None if RITMA_TSA_URL is not set.
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("RITMA_TSA_URL").ok()?;
        if url.trim().is_empty() {
            return None;
        }

        let hash_alg =
            std::env::var("RITMA_TSA_HASH_ALG").unwrap_or_else(|_| "SHA-256".to_string());
        let timeout_secs = std::env::var("RITMA_TSA_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        Some(Self {
            url,
            hash_alg,
            timeout_secs,
        })
    }
}

/// Timestamp token response
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimestampToken {
    /// Base64-encoded DER timestamp token
    pub token_b64: String,
    /// SHA-256 hash of the token for reference
    pub token_hash: String,
    /// Timestamp from token (if parseable)
    pub timestamp: Option<String>,
    /// TSA URL used
    pub tsa_url: String,
    /// Hash algorithm used
    pub hash_alg: String,
}

/// Request a timestamp token from a TSA for the given data hash.
///
/// Per RFC 3161:
/// 1. Compute hash of data
/// 2. Send TimeStampReq to TSA
/// 3. Receive TimeStampResp with signed token
///
/// Returns the raw DER-encoded token bytes.
#[cfg(feature = "tsa")]
pub fn request_timestamp(data_hash: &[u8], config: &TsaConfig) -> Result<TimestampToken, String> {
    use base64::Engine;

    // Build minimal RFC 3161 TimeStampReq
    // This is a simplified ASN.1 structure - production would use proper ASN.1 library
    let ts_req = build_timestamp_request(data_hash, &config.hash_alg)?;

    // Send to TSA
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| format!("http client error: {e}"))?;

    let resp = client
        .post(&config.url)
        .header("Content-Type", "application/timestamp-query")
        .body(ts_req)
        .send()
        .map_err(|e| format!("TSA request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("TSA returned status {}", resp.status()));
    }

    let token_bytes = resp
        .bytes()
        .map_err(|e| format!("read TSA response: {e}"))?
        .to_vec();

    // Compute token hash for reference
    let mut hasher = Sha256::new();
    hasher.update(&token_bytes);
    let token_hash = hex::encode(hasher.finalize());

    Ok(TimestampToken {
        token_b64: base64::engine::general_purpose::STANDARD.encode(&token_bytes),
        token_hash,
        timestamp: None, // Would need ASN.1 parsing to extract
        tsa_url: config.url.clone(),
        hash_alg: config.hash_alg.clone(),
    })
}

#[cfg(not(feature = "tsa"))]
pub fn request_timestamp(_data_hash: &[u8], _config: &TsaConfig) -> Result<TimestampToken, String> {
    Err("TSA feature not enabled. Build with --features tsa".to_string())
}

/// Build a minimal RFC 3161 TimeStampReq
///
/// ASN.1 structure:
/// TimeStampReq ::= SEQUENCE {
///    version         INTEGER { v1(1) },
///    messageImprint  MessageImprint,
///    reqPolicy       OBJECT IDENTIFIER OPTIONAL,
///    nonce           INTEGER OPTIONAL,
///    certReq         BOOLEAN DEFAULT FALSE,
///    extensions      [0] IMPLICIT Extensions OPTIONAL
/// }
///
/// MessageImprint ::= SEQUENCE {
///    hashAlgorithm   AlgorithmIdentifier,
///    hashedMessage   OCTET STRING
/// }
#[cfg(feature = "tsa")]
fn build_timestamp_request(hash: &[u8], _alg: &str) -> Result<Vec<u8>, String> {
    // SHA-256 OID: 2.16.840.1.101.3.4.2.1
    let sha256_oid: [u8; 11] = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];

    // Build AlgorithmIdentifier (SEQUENCE { OID, NULL })
    let mut alg_id = Vec::new();
    alg_id.extend_from_slice(&sha256_oid);
    alg_id.extend_from_slice(&[0x05, 0x00]); // NULL parameters
    let alg_seq = asn1_sequence(&alg_id);

    // Build MessageImprint (SEQUENCE { AlgorithmIdentifier, OCTET STRING })
    let hash_octet = asn1_octet_string(hash);
    let mut msg_imprint = Vec::new();
    msg_imprint.extend_from_slice(&alg_seq);
    msg_imprint.extend_from_slice(&hash_octet);
    let msg_imprint_seq = asn1_sequence(&msg_imprint);

    // Build TimeStampReq (SEQUENCE { INTEGER(1), MessageImprint, certReq=TRUE })
    let mut ts_req = Vec::new();
    ts_req.extend_from_slice(&[0x02, 0x01, 0x01]); // version INTEGER 1
    ts_req.extend_from_slice(&msg_imprint_seq);
    ts_req.extend_from_slice(&[0x01, 0x01, 0xFF]); // certReq BOOLEAN TRUE

    Ok(asn1_sequence(&ts_req))
}

#[cfg(feature = "tsa")]
fn asn1_sequence(content: &[u8]) -> Vec<u8> {
    let mut result = vec![0x30]; // SEQUENCE tag
    result.extend(asn1_length(content.len()));
    result.extend_from_slice(content);
    result
}

#[cfg(feature = "tsa")]
fn asn1_octet_string(content: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING tag
    result.extend(asn1_length(content.len()));
    result.extend_from_slice(content);
    result
}

#[cfg(feature = "tsa")]
fn asn1_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// Compute SHA-256 hash of data for timestamping
pub fn hash_for_timestamp(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Try to get a timestamp token if TSA is configured.
/// Returns None if TSA is not configured or request fails.
pub fn try_get_timestamp(data: &[u8]) -> Option<TimestampToken> {
    let config = TsaConfig::from_env()?;
    let hash = hash_for_timestamp(data);
    request_timestamp(&hash, &config).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_for_timestamp() {
        let data = b"test data";
        let hash = hash_for_timestamp(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_tsa_config_missing() {
        std::env::remove_var("RITMA_TSA_URL");
        assert!(TsaConfig::from_env().is_none());
    }
}
