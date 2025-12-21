// Enterprise-grade evidence packaging for Ritma
// Produces signed, verifiable evidence bundles for auditors and regulators

pub mod manifest;
pub mod builder;
pub mod signer;
pub mod verifier;

pub use manifest::{
    EvidencePackageManifest, PackageScope, PackageArtifact, PackageChainHeads,
    PackageSecurity, SignatureType, ArtifactType,
};
pub use builder::PackageBuilder;
pub use signer::{PackageSigner, SigningKey};
pub use verifier::{PackageVerifier, VerificationResult, VerificationError};

use serde::{Deserialize, Serialize};

/// Package format version for schema evolution
pub const PACKAGE_FORMAT_VERSION: u32 = 1;

/// Result type for package operations
pub type PackageResult<T> = Result<T, PackageError>;

/// Errors that can occur during package operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackageError {
    InvalidScope(String),
    MissingArtifact(String),
    HashMismatch { expected: String, actual: String },
    SignatureInvalid(String),
    ChainVerificationFailed(String),
    IoError(String),
    SerializationError(String),
    MissingSigningKey,
    InvalidSigningKey(String),
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidScope(s) => write!(f, "Invalid scope: {}", s),
            Self::MissingArtifact(s) => write!(f, "Missing artifact: {}", s),
            Self::HashMismatch { expected, actual } => {
                write!(f, "Hash mismatch: expected {}, got {}", expected, actual)
            }
            Self::SignatureInvalid(s) => write!(f, "Invalid signature: {}", s),
            Self::ChainVerificationFailed(s) => write!(f, "Chain verification failed: {}", s),
            Self::IoError(s) => write!(f, "IO error: {}", s),
            Self::SerializationError(s) => write!(f, "Serialization error: {}", s),
            Self::MissingSigningKey => write!(f, "Missing signing key"),
            Self::InvalidSigningKey(s) => write!(f, "Invalid signing key: {}", s),
        }
    }
}

impl std::error::Error for PackageError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_format_version_is_stable() {
        assert_eq!(PACKAGE_FORMAT_VERSION, 1);
    }
}
