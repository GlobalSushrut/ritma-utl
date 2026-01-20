//! COSE_Sign1 signature format per RFC 9052 §4.2.
//!
//! Per spec §1.2: window_page.sig.cose uses COSE_Sign1 format.
//!
//! COSE_Sign1 = [
//!   protected: << { 1: alg, 3: content_type } >>,
//!   unprotected: {},
//!   payload: << data bytes >>,
//!   signature: << sig bytes >>
//! ]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// COSE algorithm identifiers
pub const ALG_ES256: i64 = -7; // ECDSA w/ SHA-256 on P-256
pub const ALG_EDDSA: i64 = -8; // EdDSA (Ed25519)

/// Content type for Ritma pages
pub const CONTENT_TYPE_RITMA_PAGE: &str = "application/ritma-page+cbor";

/// COSE_Sign1 structure
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    pub protected: Vec<u8>,
    pub unprotected: std::collections::HashMap<i64, ciborium::Value>,
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    /// Create a new COSE_Sign1 signature for the given payload using Ed25519.
    pub fn sign_ed25519(payload: &[u8], signing_key: &SigningKey) -> Result<Self, String> {
        // Build protected header: { 1: -8 (EdDSA), 3: content_type }
        let protected_map = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(ALG_EDDSA.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Text(CONTENT_TYPE_RITMA_PAGE.to_string()),
            ),
        ]);

        let mut protected_bytes = Vec::new();
        ciborium::into_writer(&protected_map, &mut protected_bytes)
            .map_err(|e| format!("encode protected header: {e}"))?;

        // Sig_structure per RFC 9052 §4.4:
        // Sig_structure = ["Signature1", protected, external_aad, payload]
        let sig_structure = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".to_string()),
            ciborium::Value::Bytes(protected_bytes.clone()),
            ciborium::Value::Bytes(vec![]), // empty external AAD
            ciborium::Value::Bytes(payload.to_vec()),
        ]);

        let mut to_sign = Vec::new();
        ciborium::into_writer(&sig_structure, &mut to_sign)
            .map_err(|e| format!("encode sig_structure: {e}"))?;

        // Sign with Ed25519
        let signature = signing_key.sign(&to_sign);

        Ok(Self {
            protected: protected_bytes,
            unprotected: std::collections::HashMap::new(),
            payload: Some(payload.to_vec()),
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Verify a COSE_Sign1 signature using Ed25519.
    pub fn verify_ed25519(&self, verifying_key: &VerifyingKey) -> Result<bool, String> {
        let payload = self.payload.as_ref().ok_or("missing payload")?;

        // Reconstruct Sig_structure
        let sig_structure = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".to_string()),
            ciborium::Value::Bytes(self.protected.clone()),
            ciborium::Value::Bytes(vec![]), // empty external AAD
            ciborium::Value::Bytes(payload.clone()),
        ]);

        let mut to_verify = Vec::new();
        ciborium::into_writer(&sig_structure, &mut to_verify)
            .map_err(|e| format!("encode sig_structure: {e}"))?;

        // Verify signature
        if self.signature.len() != 64 {
            return Err(format!(
                "invalid signature length: {}",
                self.signature.len()
            ));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let signature = Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(&to_verify, &signature).is_ok())
    }

    /// Encode to CBOR bytes (COSE_Sign1 array format)
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let cose_array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(self.protected.clone()),
            ciborium::Value::Map(vec![]), // empty unprotected header
            self.payload
                .as_ref()
                .map(|p| ciborium::Value::Bytes(p.clone()))
                .unwrap_or(ciborium::Value::Null),
            ciborium::Value::Bytes(self.signature.clone()),
        ]);

        // Tag 18 for COSE_Sign1
        let tagged = ciborium::Value::Tag(18, Box::new(cose_array));

        let mut buf = Vec::new();
        ciborium::into_writer(&tagged, &mut buf).map_err(|e| format!("encode COSE_Sign1: {e}"))?;

        Ok(buf)
    }

    /// Decode from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        let value: ciborium::Value =
            ciborium::from_reader(bytes).map_err(|e| format!("decode COSE_Sign1: {e}"))?;

        // Expect Tag(18, Array)
        let array = match value {
            ciborium::Value::Tag(18, inner) => match *inner {
                ciborium::Value::Array(arr) => arr,
                _ => return Err("COSE_Sign1 must contain array".to_string()),
            },
            ciborium::Value::Array(arr) => arr, // Allow untagged for flexibility
            _ => return Err("expected COSE_Sign1 structure".to_string()),
        };

        if array.len() != 4 {
            return Err(format!(
                "COSE_Sign1 array must have 4 elements, got {}",
                array.len()
            ));
        }

        let protected = match &array[0] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => return Err("protected header must be bytes".to_string()),
        };

        let payload = match &array[2] {
            ciborium::Value::Bytes(b) => Some(b.clone()),
            ciborium::Value::Null => None,
            _ => return Err("payload must be bytes or null".to_string()),
        };

        let signature = match &array[3] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => return Err("signature must be bytes".to_string()),
        };

        Ok(Self {
            protected,
            unprotected: std::collections::HashMap::new(),
            payload,
            signature,
        })
    }
}

/// Sign data and return COSE_Sign1 CBOR bytes.
/// Uses Ed25519 key from node_keystore if available.
///
/// Note: This uses node_keystore's sign_bytes internally and wraps in COSE format.
pub fn sign_cose(payload: &[u8], key_id: &str) -> Result<Vec<u8>, String> {
    let ks = node_keystore::NodeKeystore::from_env().map_err(|e| format!("load keystore: {e}"))?;

    // Build protected header
    let protected_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(ALG_EDDSA.into()),
        ),
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Text(CONTENT_TYPE_RITMA_PAGE.to_string()),
        ),
    ]);

    let mut protected_bytes = Vec::new();
    ciborium::into_writer(&protected_map, &mut protected_bytes)
        .map_err(|e| format!("encode protected header: {e}"))?;

    // Build Sig_structure per RFC 9052 §4.4
    let sig_structure = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".to_string()),
        ciborium::Value::Bytes(protected_bytes.clone()),
        ciborium::Value::Bytes(vec![]), // empty external AAD
        ciborium::Value::Bytes(payload.to_vec()),
    ]);

    let mut to_sign = Vec::new();
    ciborium::into_writer(&sig_structure, &mut to_sign)
        .map_err(|e| format!("encode sig_structure: {e}"))?;

    // Sign using keystore
    let sig_hex = ks
        .sign_bytes(key_id, &to_sign)
        .map_err(|e| format!("sign failed: {e}"))?;
    let signature = hex::decode(&sig_hex).map_err(|e| format!("decode signature: {e}"))?;

    // Build COSE_Sign1
    let cose = CoseSign1 {
        protected: protected_bytes,
        unprotected: std::collections::HashMap::new(),
        payload: Some(payload.to_vec()),
        signature,
    };

    cose.to_cbor()
}

/// Verify COSE_Sign1 signature given the CBOR bytes and public key.
pub fn verify_cose(cose_bytes: &[u8], public_key_bytes: &[u8]) -> Result<bool, String> {
    if public_key_bytes.len() != 32 {
        return Err(format!(
            "invalid public key length: {}",
            public_key_bytes.len()
        ));
    }

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(public_key_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("invalid public key: {e}"))?;

    let cose = CoseSign1::from_cbor(cose_bytes)?;
    cose.verify_ed25519(&verifying_key)
}

/// Compute SHA-256 hash of data
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_cose_sign_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let payload = b"test payload data";
        let cose = CoseSign1::sign_ed25519(payload, &signing_key).unwrap();

        // Verify
        assert!(cose.verify_ed25519(&verifying_key).unwrap());

        // Roundtrip through CBOR
        let cbor = cose.to_cbor().unwrap();
        let decoded = CoseSign1::from_cbor(&cbor).unwrap();
        assert!(decoded.verify_ed25519(&verifying_key).unwrap());
    }

    #[test]
    fn test_cose_tampered_payload() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let payload = b"test payload data";
        let mut cose = CoseSign1::sign_ed25519(payload, &signing_key).unwrap();

        // Tamper with payload
        cose.payload = Some(b"tampered data".to_vec());

        // Verification should fail
        assert!(!cose.verify_ed25519(&verifying_key).unwrap());
    }
}
