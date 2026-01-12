// Cryptographic signing for evidence packages

use crate::manifest::{EvidencePackageManifest, PackageSignature, SignatureType};
use crate::{PackageError, PackageResult};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Signing key types
pub enum SigningKey {
    HmacSha256(Vec<u8>),
    Ed25519(ed25519_dalek::SigningKey),
    None,
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        if let SigningKey::HmacSha256(ref mut b) = self {
            b.zeroize();
        }
    }
}

impl SigningKey {
    /// Load from hex string
    pub fn from_hex(key_type: &str, hex: &str) -> PackageResult<Self> {
        match key_type.to_lowercase().as_str() {
            "hmac_sha256" | "hmac" => {
                let bytes = hex::decode(hex)
                    .map_err(|e| PackageError::InvalidSigningKey(format!("invalid hex: {e}")))?;
                Ok(Self::HmacSha256(bytes))
            }
            "ed25519" => {
                let mut bytes = hex::decode(hex)
                    .map_err(|e| PackageError::InvalidSigningKey(format!("invalid hex: {e}")))?;
                if bytes.len() != 32 {
                    bytes.zeroize();
                    return Err(PackageError::InvalidSigningKey(
                        "ed25519 key must be 32 bytes".to_string(),
                    ));
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&bytes);
                bytes.zeroize();
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                key_bytes.zeroize();
                Ok(Self::Ed25519(signing_key))
            }
            _ => Err(PackageError::InvalidSigningKey(format!(
                "unsupported key type: {key_type}"
            ))),
        }
    }

    /// Generate a new ed25519 key
    pub fn generate_ed25519() -> Self {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        let signing_key = SigningKey::from_bytes(&rand::Rng::gen(&mut csprng));
        Self::Ed25519(signing_key)
    }

    /// Get signature type
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::HmacSha256(_) => SignatureType::HmacSha256,
            Self::Ed25519(_) => SignatureType::Ed25519,
            Self::None => SignatureType::None,
        }
    }
}

/// Package signer
pub struct PackageSigner {
    key: SigningKey,
    signer_id: String,
}

impl PackageSigner {
    pub fn new(key: SigningKey, signer_id: String) -> Self {
        Self { key, signer_id }
    }

    /// Load from environment variable
    pub fn from_env(env_var: &str, signer_id: String) -> PackageResult<Self> {
        let mut key_spec = std::env::var(env_var).map_err(|_| PackageError::MissingSigningKey)?;

        // Format: "type:hex_key" e.g., "hmac:abcd1234" or "ed25519:..."
        let parts: Vec<&str> = key_spec.splitn(2, ':').collect();
        if parts.len() != 2 {
            key_spec.zeroize();
            return Err(PackageError::InvalidSigningKey(
                "expected format: type:hex_key".to_string(),
            ));
        }

        let key = SigningKey::from_hex(parts[0], parts[1])?;
        key_spec.zeroize();
        Ok(Self::new(key, signer_id))
    }

    /// Sign a manifest
    pub fn sign(&self, manifest: &mut EvidencePackageManifest) -> PackageResult<()> {
        // Compute package hash
        let package_hash = manifest
            .compute_hash()
            .map_err(PackageError::SerializationError)?;
        manifest.security.package_hash = package_hash.clone();

        // Sign the hash
        let signature_hex = match &self.key {
            SigningKey::HmacSha256(key_bytes) => {
                let mut mac = HmacSha256::new_from_slice(key_bytes)
                    .map_err(|e| PackageError::InvalidSigningKey(format!("HMAC error: {e}")))?;
                mac.update(package_hash.as_bytes());
                let result = mac.finalize();
                hex::encode(result.into_bytes())
            }
            SigningKey::Ed25519(signing_key) => {
                use ed25519_dalek::Signer;
                let signature = signing_key.sign(package_hash.as_bytes());
                hex::encode(signature.to_bytes())
            }
            SigningKey::None => {
                // No signature
                manifest.security.signature = None;
                return Ok(());
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let public_key_hex = match &self.key {
            SigningKey::Ed25519(signing_key) => {
                let verifying_key = signing_key.verifying_key();
                Some(hex::encode(verifying_key.to_bytes()))
            }
            _ => None,
        };

        manifest.security.signature = Some(PackageSignature {
            signature_type: self.key.signature_type(),
            signature_hex,
            signer_id: self.signer_id.clone(),
            signed_at: now,
            public_key_hex,
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;
    use std::collections::HashMap;

    fn make_test_manifest() -> EvidencePackageManifest {
        EvidencePackageManifest {
            package_id: "pkg_test".to_string(),
            format_version: 1,
            created_at: 1000,
            created_by: None,
            tenant_id: "test_tenant".to_string(),
            scope: PackageScope::PolicyCommit {
                commit_id: "commit_123".to_string(),
                framework: None,
            },
            chain_heads: PackageChainHeads {
                dig_index_head: "head_abc".to_string(),
                policy_ledger_head: None,
                svc_ledger_head: None,
                burn_chain_head: None,
                search_events_head: None,
            },
            artifacts: vec![],
            security: PackageSecurity {
                hash_algorithm: "sha256".to_string(),
                package_hash: String::new(),
                signature: None,
            },
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn sign_with_hmac() {
        let key = SigningKey::HmacSha256(vec![0x42; 32]);
        let signer = PackageSigner::new(key, "test_signer".to_string());

        let mut manifest = make_test_manifest();
        signer.sign(&mut manifest).expect("sign");

        assert!(!manifest.security.package_hash.is_empty());
        assert!(manifest.security.signature.is_some());

        let sig = manifest.security.signature.unwrap();
        assert_eq!(sig.signer_id, "test_signer");
        assert!(!sig.signature_hex.is_empty());
    }

    #[test]
    fn sign_with_ed25519() {
        let key = SigningKey::generate_ed25519();
        let signer = PackageSigner::new(key, "ed_signer".to_string());

        let mut manifest = make_test_manifest();
        signer.sign(&mut manifest).expect("sign");

        let sig = manifest.security.signature.unwrap();
        assert!(matches!(sig.signature_type, SignatureType::Ed25519));
        assert!(sig.public_key_hex.is_some());
    }
}
