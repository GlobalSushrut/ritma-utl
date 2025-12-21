use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
struct KeyRecord {
    key_id: String,
    alg: String,
    secret_hex: String,
    label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub key_id: String,
    pub key_hash: String,
    pub label: Option<String>,
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

#[derive(Debug, Clone)]
pub enum KeystoreKey {
    HmacSha256(Vec<u8>),
    Ed25519(Ed25519SigningKey),
}

type HmacSha256 = Hmac<Sha256>;

impl NodeKeystore {
    pub fn from_env() -> Result<Self, KeystoreError> {
        let path = std::env::var("RITMA_KEYSTORE_PATH")
            .unwrap_or_else(|_| "./node_keystore.json".to_string());
        Self::from_path(path)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, KeystoreError> {
        let data = fs::read_to_string(path)?;
        let keys: Vec<KeyRecord> = serde_json::from_str(&data)?;
        Ok(Self { keys })
    }

    pub fn list_metadata(&self) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let mut out = Vec::new();
        for rec in &self.keys {
            let hash = self.compute_key_hash(rec)?;
            out.push(KeyMetadata {
                key_id: rec.key_id.clone(),
                key_hash: hash,
                label: rec.label.clone(),
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
        let hash = self.compute_key_hash(rec)?;
        Ok(KeyMetadata {
            key_id: rec.key_id.clone(),
            key_hash: hash,
            label: rec.label.clone(),
        })
    }

    pub fn key_for_signing(&self, key_id: &str) -> Result<KeystoreKey, KeystoreError> {
        let rec = self
            .keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| KeystoreError::UnknownKey(key_id.to_string()))?;

        let bytes = hex::decode(&rec.secret_hex)
            .map_err(|_| KeystoreError::InvalidKey(rec.key_id.clone()))?;

        let alg = rec.alg.to_lowercase();
        if alg == "hmac" || alg == "hmac_sha256" {
            return Ok(KeystoreKey::HmacSha256(bytes));
        }

        if alg == "ed25519" {
            if bytes.len() != 32 {
                return Err(KeystoreError::InvalidKey(rec.key_id.clone()));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
            return Ok(KeystoreKey::Ed25519(signing_key));
        }

        Err(KeystoreError::InvalidKey(rec.key_id.clone()))
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

        let bytes = hex::decode(&rec.secret_hex)
            .map_err(|_| KeystoreError::InvalidKey(rec.key_id.clone()))?;
        let alg = rec.alg.to_lowercase();

        if alg == "hmac" || alg == "hmac_sha256" {
            let mut mac = HmacSha256::new_from_slice(&bytes)
                .map_err(|_| KeystoreError::InvalidKey(rec.key_id.clone()))?;
            mac.update(payload);
            let result = mac.finalize();
            return Ok(hex::encode(result.into_bytes()));
        }

        if alg == "ed25519" {
            use ed25519_dalek::Signer;

            if bytes.len() != 32 {
                return Err(KeystoreError::InvalidKey(rec.key_id.clone()));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
            let sig = signing_key.sign(payload);
            return Ok(hex::encode(sig.to_bytes()));
        }

        Err(KeystoreError::InvalidKey(rec.key_id.clone()))
    }

    fn compute_key_hash(&self, rec: &KeyRecord) -> Result<String, KeystoreError> {
        let bytes = hex::decode(&rec.secret_hex)
            .map_err(|_| KeystoreError::InvalidKey(rec.key_id.clone()))?;
        let alg = rec.alg.to_lowercase();

        if alg == "ed25519" {
            if bytes.len() != 32 {
                return Err(KeystoreError::InvalidKey(rec.key_id.clone()));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
            let verifying = signing_key.verifying_key();
            let mut hasher = Sha256::new();
            hasher.update(verifying.to_bytes());
            let digest = hasher.finalize();
            return Ok(hex::encode(digest));
        }

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        Ok(hex::encode(digest))
    }
}
