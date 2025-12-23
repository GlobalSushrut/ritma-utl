// Verification of evidence packages

use crate::manifest::{EvidencePackageManifest, SignatureType};
use crate::{PackageError, PackageResult};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub package_id: String,
    pub hash_valid: bool,
    pub signature_valid: bool,
    pub artifacts_verified: usize,
    pub artifacts_failed: usize,
    pub errors: Vec<String>,
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        self.hash_valid && self.signature_valid && self.artifacts_failed == 0
    }
}

/// Verification errors
#[derive(Debug, Clone)]
pub enum VerificationError {
    HashMismatch,
    SignatureMissing,
    SignatureInvalid,
    ArtifactMissing(String),
    ArtifactHashMismatch(String),
}

/// Package verifier
pub struct PackageVerifier {
    verify_artifacts: bool,
}

impl PackageVerifier {
    pub fn new() -> Self {
        Self {
            verify_artifacts: true,
        }
    }

    pub fn skip_artifacts(mut self) -> Self {
        self.verify_artifacts = false;
        self
    }

    /// Verify a package manifest
    pub fn verify(&self, manifest: &EvidencePackageManifest) -> VerificationResult {
        let mut result = VerificationResult {
            package_id: manifest.package_id.clone(),
            hash_valid: false,
            signature_valid: false,
            artifacts_verified: 0,
            artifacts_failed: 0,
            errors: Vec::new(),
        };

        // Verify package hash
        match manifest.verify_hash() {
            Ok(_) => result.hash_valid = true,
            Err(e) => result.errors.push(format!("Hash verification failed: {e}")),
        }

        // Verify signature
        if let Some(ref sig) = manifest.security.signature {
            match self.verify_signature(manifest, sig) {
                Ok(_) => result.signature_valid = true,
                Err(e) => result
                    .errors
                    .push(format!("Signature verification failed: {e}")),
            }
        } else {
            result.errors.push("No signature present".to_string());
        }

        // Verify artifacts if requested
        if self.verify_artifacts {
            for artifact in &manifest.artifacts {
                if let Some(ref path) = artifact.path {
                    match self.verify_artifact_hash(path, &artifact.hash) {
                        Ok(_) => result.artifacts_verified += 1,
                        Err(e) => {
                            result.artifacts_failed += 1;
                            result.errors.push(format!(
                                "Artifact {} verification failed: {e}",
                                artifact.artifact_id
                            ));
                        }
                    }
                }
            }
        }

        result
    }

    fn verify_signature(
        &self,
        manifest: &EvidencePackageManifest,
        sig: &crate::manifest::PackageSignature,
    ) -> PackageResult<()> {
        let package_hash = &manifest.security.package_hash;

        match sig.signature_type {
            SignatureType::HmacSha256 => {
                // For HMAC, we need the key from environment
                if let Ok(key_hex) = std::env::var("UTLD_PACKAGE_VERIFY_KEY") {
                    let key_bytes = hex::decode(&key_hex).map_err(|e| {
                        PackageError::InvalidSigningKey(format!("invalid hex: {e}"))
                    })?;

                    let mut mac = HmacSha256::new_from_slice(&key_bytes)
                        .map_err(|e| PackageError::InvalidSigningKey(format!("HMAC error: {e}")))?;
                    mac.update(package_hash.as_bytes());

                    let expected = hex::decode(&sig.signature_hex).map_err(|e| {
                        PackageError::SignatureInvalid(format!("invalid sig hex: {e}"))
                    })?;

                    mac.verify_slice(&expected)
                        .map_err(|_| PackageError::SignatureInvalid("HMAC mismatch".to_string()))?;

                    Ok(())
                } else {
                    Err(PackageError::SignatureInvalid(
                        "UTLD_PACKAGE_VERIFY_KEY not set for HMAC verification".to_string(),
                    ))
                }
            }
            SignatureType::Ed25519 => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};

                let public_key_hex = sig.public_key_hex.as_ref().ok_or_else(|| {
                    PackageError::SignatureInvalid("missing public key".to_string())
                })?;

                let public_key_bytes = hex::decode(public_key_hex).map_err(|e| {
                    PackageError::SignatureInvalid(format!("invalid pubkey hex: {e}"))
                })?;

                if public_key_bytes.len() != 32 {
                    return Err(PackageError::SignatureInvalid(
                        "invalid pubkey length".to_string(),
                    ));
                }

                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&public_key_bytes);

                let verifying_key = VerifyingKey::from_bytes(&key_array)
                    .map_err(|e| PackageError::SignatureInvalid(format!("invalid pubkey: {e}")))?;

                let sig_bytes = hex::decode(&sig.signature_hex)
                    .map_err(|e| PackageError::SignatureInvalid(format!("invalid sig hex: {e}")))?;

                if sig_bytes.len() != 64 {
                    return Err(PackageError::SignatureInvalid(
                        "invalid sig length".to_string(),
                    ));
                }

                let mut sig_array = [0u8; 64];
                sig_array.copy_from_slice(&sig_bytes);

                let signature = Signature::from_bytes(&sig_array);

                verifying_key
                    .verify(package_hash.as_bytes(), &signature)
                    .map_err(|e| {
                        PackageError::SignatureInvalid(format!("ed25519 verify failed: {e}"))
                    })?;

                Ok(())
            }
            SignatureType::None => Err(PackageError::SignatureInvalid(
                "no signature type".to_string(),
            )),
        }
    }

    fn verify_artifact_hash(&self, path: &str, expected_hash: &str) -> PackageResult<()> {
        let content = std::fs::read(path)
            .map_err(|e| PackageError::IoError(format!("failed to read {path}: {e}")))?;

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();
        let actual_hash = hex::encode(hash);

        if actual_hash != expected_hash {
            return Err(PackageError::HashMismatch {
                expected: expected_hash.to_string(),
                actual: actual_hash,
            });
        }

        Ok(())
    }
}

impl Default for PackageVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;
    use crate::signer::*;
    use std::collections::HashMap;

    fn make_test_manifest() -> EvidencePackageManifest {
        EvidencePackageManifest {
            package_id: "pkg_verify_test".to_string(),
            format_version: 1,
            created_at: 2000,
            created_by: None,
            tenant_id: "test_tenant".to_string(),
            scope: PackageScope::PolicyCommit {
                commit_id: "commit_xyz".to_string(),
                framework: None,
            },
            chain_heads: PackageChainHeads {
                dig_index_head: "head_def".to_string(),
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
    fn verify_unsigned_package() {
        let manifest = make_test_manifest();
        let verifier = PackageVerifier::new().skip_artifacts();
        let result = verifier.verify(&manifest);

        assert!(!result.is_valid());
        assert!(!result.signature_valid);
    }

    #[test]
    fn verify_signed_package_ed25519() {
        let key = SigningKey::generate_ed25519();
        let signer = PackageSigner::new(key, "test_signer".to_string());

        let mut manifest = make_test_manifest();
        signer.sign(&mut manifest).expect("sign");

        let verifier = PackageVerifier::new().skip_artifacts();
        let result = verifier.verify(&manifest);

        assert!(result.hash_valid);
        assert!(result.signature_valid);
        assert!(result.is_valid());
    }
}
