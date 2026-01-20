use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;

pub mod tpm;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
pub use tpm::{
    AttestationBinding, AttestationResult, PcrBank, PcrSelection, TpmAttestor, TpmError, TpmQuote,
};
use zeroize::Zeroize;

#[derive(Debug, Clone, Deserialize)]
struct KeyRecord {
    key_id: String,
    alg: String,
    secret_hex: String,
    label: Option<String>,
}

impl Drop for KeyRecord {
    fn drop(&mut self) {
        self.secret_hex.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreKey {
    pub key_id: String,
    pub key_type: String,
    #[serde(skip_serializing)] // Don't serialize secrets
    pub key_material: String,
    pub metadata: HashMap<String, String>,
}

impl Drop for KeystoreKey {
    fn drop(&mut self) {
        // Manually zero out the key material
        self.key_material.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub key_id: String,
    pub key_hash: String,
    pub label: Option<String>,
    pub public_key_hex: Option<String>,
}

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("failed to read keystore file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse keystore JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("unknown key id: {0}")]
    UnknownKey(String),
    #[error("invalid key material for {0}")]
    InvalidKey(String),
}

#[derive(Debug, Clone)]
pub struct NodeKeystore {
    keys: Vec<KeyRecord>,
}

impl Drop for NodeKeystore {
    fn drop(&mut self) {
        // Ensure all secrets are wiped when keystore is dropped
        for rec in &mut self.keys {
            rec.secret_hex.zeroize();
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

impl NodeKeystore {
    pub fn from_env() -> Result<Self, KeystoreError> {
        let path = std::env::var("RITMA_KEYSTORE_PATH")
            .unwrap_or_else(|_| "./node_keystore.json".to_string());
        Self::from_path(path)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, KeystoreError> {
        let mut data = fs::read_to_string(path)?;
        let keys: Vec<KeyRecord> = serde_json::from_str(&data)?;
        data.zeroize();
        Ok(Self { keys })
    }

    pub fn list_metadata(&self) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let mut out = Vec::new();
        for rec in &self.keys {
            let (hash, public_key_hex) = self.compute_key_hash_and_pub(rec)?;
            out.push(KeyMetadata {
                key_id: rec.key_id.clone(),
                key_hash: hash,
                label: rec.label.clone(),
                public_key_hex,
            });
        }
        Ok(out)
    }

    pub fn metadata_for(&self, key_id: &str) -> Result<KeyMetadata, KeystoreError> {
        let rec = self
            .keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| KeystoreError::UnknownKey(key_id.to_string()))?;
        let (hash, public_key_hex) = self.compute_key_hash_and_pub(rec)?;
        Ok(KeyMetadata {
            key_id: rec.key_id.clone(),
            key_hash: hash,
            label: rec.label.clone(),
            public_key_hex,
        })
    }

    pub fn key_for_signing(&self, key_id: &str) -> Result<KeystoreKey, KeystoreError> {
        let rec = self
            .keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| KeystoreError::UnknownKey(key_id.to_string()))?;

        let alg = rec.alg.to_lowercase();

        Ok(KeystoreKey {
            key_id: rec.key_id.clone(),
            key_type: alg.clone(),
            key_material: rec.secret_hex.clone(),
            metadata: HashMap::new(),
        })
    }

    /// Sign an arbitrary payload using the key identified by key_id.
    ///
    /// The result is returned as a hex-encoded string of the raw signature or MAC.
    pub fn sign_bytes(&self, key_id: &str, payload: &[u8]) -> Result<String, KeystoreError> {
        let rec = self
            .keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| KeystoreError::UnknownKey(key_id.to_string()))?;

        let mut bytes = hex::decode(&rec.secret_hex)
            .map_err(|_| KeystoreError::InvalidKey(rec.key_id.clone()))?;
        let alg = rec.alg.to_lowercase();

        if alg == "hmac" || alg == "hmac_sha256" {
            let mut mac = HmacSha256::new_from_slice(&bytes)
                .map_err(|_| KeystoreError::InvalidKey(rec.key_id.clone()))?;
            mac.update(payload);
            let result = mac.finalize();
            let out = hex::encode(result.into_bytes());
            bytes.zeroize();
            return Ok(out);
        }

        if alg == "ed25519" {
            if bytes.len() != 32 {
                bytes.zeroize();
                return Err(KeystoreError::InvalidKey(rec.key_id.clone()));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);
            use ed25519_dalek::Signer;
            let signature = signing_key.sign(payload);
            key_bytes.zeroize();
            bytes.zeroize();
            return Ok(hex::encode(signature.to_bytes()));
        }

        bytes.zeroize();

        Err(KeystoreError::InvalidKey(rec.key_id.clone()))
    }

    fn compute_key_hash_and_pub(
        &self,
        rec: &KeyRecord,
    ) -> Result<(String, Option<String>), KeystoreError> {
        let mut bytes = hex::decode(&rec.secret_hex)
            .map_err(|_| KeystoreError::InvalidKey(rec.key_id.clone()))?;
        let alg = rec.alg.to_lowercase();

        if alg == "ed25519" {
            if bytes.len() != 32 {
                bytes.zeroize();
                return Err(KeystoreError::InvalidKey(rec.key_id.clone()));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let verifying = signing_key.verifying_key();
            let mut hasher = Sha256::new();
            hasher.update(verifying.to_bytes());
            let digest = hasher.finalize();
            let pub_hex = hex::encode(verifying.to_bytes());
            key_bytes.zeroize();
            bytes.zeroize();
            return Ok((hex::encode(digest), Some(pub_hex)));
        }

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        bytes.zeroize();
        Ok((hex::encode(digest), None))
    }
}
