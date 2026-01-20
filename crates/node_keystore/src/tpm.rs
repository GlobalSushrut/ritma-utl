//! TPM 2.0 Hardware Attestation Module
//!
//! Provides TPM-based attestation capabilities:
//! - PCR quote generation (signed by AIK)
//! - Quote verification
//! - Graceful fallback for systems without TPM
//!
//! This module uses tpm2-tools CLI for portability across different
//! TPM implementations (hardware TPM, fTPM, swtpm).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

/// TPM attestation errors
#[derive(Debug, Error)]
pub enum TpmError {
    #[error("TPM not available: {0}")]
    NotAvailable(String),
    #[error("TPM command failed: {0}")]
    CommandFailed(String),
    #[error("invalid quote format: {0}")]
    InvalidQuote(String),
    #[error("quote verification failed: {0}")]
    VerificationFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// PCR bank algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PcrBank {
    Sha1,
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl PcrBank {
    pub fn as_str(&self) -> &'static str {
        match self {
            PcrBank::Sha1 => "sha1",
            PcrBank::Sha256 => "sha256",
            PcrBank::Sha384 => "sha384",
            PcrBank::Sha512 => "sha512",
        }
    }
}


/// PCR selection for quoting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrSelection {
    pub bank: PcrBank,
    pub indices: Vec<u8>,
}

impl Default for PcrSelection {
    fn default() -> Self {
        Self {
            bank: PcrBank::Sha256,
            // Default: PCRs 0-7 (firmware/boot measurements)
            indices: vec![0, 1, 2, 3, 4, 5, 6, 7],
        }
    }
}

impl PcrSelection {
    /// Create selection for specific PCR indices
    pub fn new(bank: PcrBank, indices: Vec<u8>) -> Self {
        Self { bank, indices }
    }

    /// Format as tpm2-tools PCR selection string (e.g., "sha256:0,1,2,3")
    pub fn to_tpm2_string(&self) -> String {
        let indices: Vec<String> = self.indices.iter().map(|i| i.to_string()).collect();
        format!("{}:{}", self.bank.as_str(), indices.join(","))
    }
}

/// TPM quote (signed PCR values)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// Quote ID (unique identifier)
    pub quote_id: String,
    /// Timestamp when quote was generated
    pub timestamp: i64,
    /// Node ID that generated the quote
    pub node_id: String,
    /// PCR selection used
    pub pcr_selection: PcrSelection,
    /// PCR values (hex-encoded)
    pub pcr_values: HashMap<u8, String>,
    /// Nonce used in quote (hex-encoded)
    pub nonce: String,
    /// Quote signature (hex-encoded)
    pub signature: String,
    /// Quote message (TPMS_ATTEST structure, hex-encoded)
    pub quote_message: String,
    /// AIK public key (hex-encoded)
    pub aik_public: String,
    /// Whether this is a software-simulated quote
    pub simulated: bool,
}

impl TpmQuote {
    /// Compute deterministic hash of quote for integrity
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-tpm-quote@0.1");
        h.update(self.quote_id.as_bytes());
        h.update(b"\x00");
        h.update(self.node_id.as_bytes());
        h.update(b"\x00");
        h.update(self.timestamp.to_le_bytes());

        // Hash PCR values in sorted order
        let mut indices: Vec<_> = self.pcr_values.keys().collect();
        indices.sort();
        for idx in indices {
            h.update([*idx]);
            h.update(self.pcr_values[idx].as_bytes());
            h.update(b"\x00");
        }

        h.update(self.nonce.as_bytes());
        h.update(b"\x00");
        h.update(self.signature.as_bytes());
        h.update(b"\x00");
        h.update(self.quote_message.as_bytes());
        h.update([if self.simulated { 1 } else { 0 }]);

        h.finalize().into()
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.compute_hash())
    }
}

/// TPM attestation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    /// Whether attestation succeeded
    pub success: bool,
    /// Quote (if successful)
    pub quote: Option<TpmQuote>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Whether TPM hardware was used
    pub hardware_tpm: bool,
}

/// TPM attestation provider
pub struct TpmAttestor {
    /// Node ID for this attestor
    node_id: String,
    /// Working directory for TPM artifacts
    work_dir: PathBuf,
    /// Whether to allow software simulation fallback
    allow_simulation: bool,
    /// Cached TPM availability check
    tpm_available: Option<bool>,
}

impl TpmAttestor {
    /// Create a new TPM attestor
    pub fn new(node_id: &str, work_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(work_dir)?;
        Ok(Self {
            node_id: node_id.to_string(),
            work_dir: work_dir.to_path_buf(),
            allow_simulation: true,
            tpm_available: None,
        })
    }

    /// Create attestor from environment
    pub fn from_env() -> std::io::Result<Self> {
        let node_id = std::env::var("RITMA_NODE_ID").unwrap_or_else(|_| "node0".to_string());
        let work_dir = std::env::var("RITMA_TPM_WORK_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("ritma_tpm"));
        Self::new(&node_id, &work_dir)
    }

    /// Disable software simulation fallback (require real TPM)
    pub fn require_hardware(mut self) -> Self {
        self.allow_simulation = false;
        self
    }

    /// Check if TPM hardware is available
    pub fn is_tpm_available(&mut self) -> bool {
        if let Some(available) = self.tpm_available {
            return available;
        }

        // Check for TPM device
        let tpm_device = Path::new("/dev/tpm0").exists() || Path::new("/dev/tpmrm0").exists();

        // Check for tpm2-tools
        let tpm2_tools = Command::new("tpm2_getcap")
            .arg("properties-fixed")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let available = tpm_device && tpm2_tools;
        self.tpm_available = Some(available);
        available
    }

    /// Generate a TPM quote
    pub fn generate_quote(
        &mut self,
        pcr_selection: &PcrSelection,
        nonce: &[u8],
    ) -> Result<TpmQuote, TpmError> {
        if self.is_tpm_available() {
            self.generate_hardware_quote(pcr_selection, nonce)
        } else if self.allow_simulation {
            self.generate_simulated_quote(pcr_selection, nonce)
        } else {
            Err(TpmError::NotAvailable(
                "TPM hardware required but not available".to_string(),
            ))
        }
    }

    /// Generate quote using hardware TPM
    fn generate_hardware_quote(
        &self,
        pcr_selection: &PcrSelection,
        nonce: &[u8],
    ) -> Result<TpmQuote, TpmError> {
        let nonce_hex = hex::encode(nonce);
        let nonce_file = self.work_dir.join("nonce.bin");
        let quote_msg_file = self.work_dir.join("quote.msg");
        let quote_sig_file = self.work_dir.join("quote.sig");
        let pcr_file = self.work_dir.join("pcr.out");
        let ak_ctx_file = self.work_dir.join("ak.ctx");
        let ak_pub_file = self.work_dir.join("ak.pub");

        // Write nonce to file
        std::fs::write(&nonce_file, nonce)?;

        // Create or load AIK
        if !ak_ctx_file.exists() {
            self.create_aik(&ak_ctx_file, &ak_pub_file)?;
        }

        // Read PCR values
        let pcr_output = Command::new("tpm2_pcrread")
            .arg(pcr_selection.to_tpm2_string())
            .arg("-o")
            .arg(&pcr_file)
            .output()?;

        if !pcr_output.status.success() {
            return Err(TpmError::CommandFailed(format!(
                "tpm2_pcrread failed: {}",
                String::from_utf8_lossy(&pcr_output.stderr)
            )));
        }

        // Parse PCR values from output
        let pcr_values =
            self.parse_pcr_output(&String::from_utf8_lossy(&pcr_output.stdout), pcr_selection)?;

        // Generate quote
        let quote_output = Command::new("tpm2_quote")
            .arg("-c")
            .arg(&ak_ctx_file)
            .arg("-l")
            .arg(pcr_selection.to_tpm2_string())
            .arg("-q")
            .arg(&nonce_hex)
            .arg("-m")
            .arg(&quote_msg_file)
            .arg("-s")
            .arg(&quote_sig_file)
            .output()?;

        if !quote_output.status.success() {
            return Err(TpmError::CommandFailed(format!(
                "tpm2_quote failed: {}",
                String::from_utf8_lossy(&quote_output.stderr)
            )));
        }

        // Read quote message and signature
        let quote_message = hex::encode(std::fs::read(&quote_msg_file)?);
        let signature = hex::encode(std::fs::read(&quote_sig_file)?);
        let aik_public = if ak_pub_file.exists() {
            hex::encode(std::fs::read(&ak_pub_file)?)
        } else {
            String::new()
        };

        Ok(TpmQuote {
            quote_id: format!("tpmq_{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().timestamp(),
            node_id: self.node_id.clone(),
            pcr_selection: pcr_selection.clone(),
            pcr_values,
            nonce: nonce_hex,
            signature,
            quote_message,
            aik_public,
            simulated: false,
        })
    }

    /// Create Attestation Identity Key
    fn create_aik(&self, ak_ctx: &Path, ak_pub: &Path) -> Result<(), TpmError> {
        let ek_ctx = self.work_dir.join("ek.ctx");

        // Create EK
        let ek_output = Command::new("tpm2_createek")
            .arg("-c")
            .arg(&ek_ctx)
            .arg("-G")
            .arg("rsa")
            .output()?;

        if !ek_output.status.success() {
            return Err(TpmError::CommandFailed(format!(
                "tpm2_createek failed: {}",
                String::from_utf8_lossy(&ek_output.stderr)
            )));
        }

        // Create AIK
        let ak_output = Command::new("tpm2_createak")
            .arg("-C")
            .arg(&ek_ctx)
            .arg("-c")
            .arg(ak_ctx)
            .arg("-G")
            .arg("rsa")
            .arg("-g")
            .arg("sha256")
            .arg("-s")
            .arg("rsassa")
            .arg("-u")
            .arg(ak_pub)
            .output()?;

        if !ak_output.status.success() {
            return Err(TpmError::CommandFailed(format!(
                "tpm2_createak failed: {}",
                String::from_utf8_lossy(&ak_output.stderr)
            )));
        }

        Ok(())
    }

    /// Parse PCR values from tpm2_pcrread output
    fn parse_pcr_output(
        &self,
        output: &str,
        selection: &PcrSelection,
    ) -> Result<HashMap<u8, String>, TpmError> {
        let mut values = HashMap::new();

        for line in output.lines() {
            // Parse lines like "  0 : 0x..."
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                if let Ok(idx) = parts[0].trim().parse::<u8>() {
                    if selection.indices.contains(&idx) {
                        let value = parts[1].trim().trim_start_matches("0x").to_string();
                        values.insert(idx, value);
                    }
                }
            }
        }

        Ok(values)
    }

    /// Generate simulated quote (software fallback)
    fn generate_simulated_quote(
        &self,
        pcr_selection: &PcrSelection,
        nonce: &[u8],
    ) -> Result<TpmQuote, TpmError> {
        let nonce_hex = hex::encode(nonce);

        // Generate deterministic simulated PCR values
        let mut pcr_values = HashMap::new();
        for idx in &pcr_selection.indices {
            let mut h = Sha256::new();
            h.update(b"simulated-pcr");
            h.update(self.node_id.as_bytes());
            h.update([*idx]);
            let value = hex::encode(h.finalize());
            pcr_values.insert(*idx, value);
        }

        // Generate simulated quote message
        let mut quote_msg = Sha256::new();
        quote_msg.update(b"simulated-quote-msg");
        quote_msg.update(nonce);
        for idx in &pcr_selection.indices {
            quote_msg.update([*idx]);
            quote_msg.update(pcr_values[idx].as_bytes());
        }
        let quote_message = hex::encode(quote_msg.finalize());

        // Generate simulated signature (HMAC with node_id as key)
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(self.node_id.as_bytes())
            .map_err(|e| TpmError::CommandFailed(e.to_string()))?;
        mac.update(quote_message.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // Generate simulated AIK public key
        let mut aik_h = Sha256::new();
        aik_h.update(b"simulated-aik-pub");
        aik_h.update(self.node_id.as_bytes());
        let aik_public = hex::encode(aik_h.finalize());

        Ok(TpmQuote {
            quote_id: format!("simq_{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().timestamp(),
            node_id: self.node_id.clone(),
            pcr_selection: pcr_selection.clone(),
            pcr_values,
            nonce: nonce_hex,
            signature,
            quote_message,
            aik_public,
            simulated: true,
        })
    }

    /// Verify a TPM quote
    pub fn verify_quote(&self, quote: &TpmQuote, expected_nonce: &[u8]) -> Result<bool, TpmError> {
        // Verify nonce matches
        let expected_nonce_hex = hex::encode(expected_nonce);
        if quote.nonce != expected_nonce_hex {
            return Err(TpmError::VerificationFailed("nonce mismatch".to_string()));
        }

        if quote.simulated {
            // For simulated quotes, verify the HMAC signature
            self.verify_simulated_quote(quote)
        } else {
            // For hardware quotes, use tpm2_checkquote
            self.verify_hardware_quote(quote)
        }
    }

    /// Verify simulated quote
    fn verify_simulated_quote(&self, quote: &TpmQuote) -> Result<bool, TpmError> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(quote.node_id.as_bytes())
            .map_err(|e| TpmError::VerificationFailed(e.to_string()))?;
        mac.update(quote.quote_message.as_bytes());

        let expected_sig = hex::encode(mac.finalize().into_bytes());
        if quote.signature != expected_sig {
            return Err(TpmError::VerificationFailed(
                "signature mismatch".to_string(),
            ));
        }

        Ok(true)
    }

    /// Verify hardware quote using tpm2_checkquote
    fn verify_hardware_quote(&self, quote: &TpmQuote) -> Result<bool, TpmError> {
        let quote_msg_file = self.work_dir.join("verify_quote.msg");
        let quote_sig_file = self.work_dir.join("verify_quote.sig");
        let ak_pub_file = self.work_dir.join("verify_ak.pub");

        // Write quote data to files
        std::fs::write(
            &quote_msg_file,
            hex::decode(&quote.quote_message).map_err(|e| TpmError::InvalidQuote(e.to_string()))?,
        )?;
        std::fs::write(
            &quote_sig_file,
            hex::decode(&quote.signature).map_err(|e| TpmError::InvalidQuote(e.to_string()))?,
        )?;
        std::fs::write(
            &ak_pub_file,
            hex::decode(&quote.aik_public).map_err(|e| TpmError::InvalidQuote(e.to_string()))?,
        )?;

        // Verify quote
        let output = Command::new("tpm2_checkquote")
            .arg("-u")
            .arg(&ak_pub_file)
            .arg("-m")
            .arg(&quote_msg_file)
            .arg("-s")
            .arg(&quote_sig_file)
            .arg("-q")
            .arg(&quote.nonce)
            .output()?;

        if !output.status.success() {
            return Err(TpmError::VerificationFailed(format!(
                "tpm2_checkquote failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(true)
    }

    /// Generate attestation for a data payload
    pub fn attest(&mut self, data: &[u8]) -> Result<AttestationResult, TpmError> {
        // Use data hash as nonce
        let mut nonce_h = Sha256::new();
        nonce_h.update(data);
        let nonce = nonce_h.finalize();

        let pcr_selection = PcrSelection::default();

        match self.generate_quote(&pcr_selection, &nonce) {
            Ok(quote) => Ok(AttestationResult {
                success: true,
                quote: Some(quote.clone()),
                error: None,
                hardware_tpm: !quote.simulated,
            }),
            Err(e) => Ok(AttestationResult {
                success: false,
                quote: None,
                error: Some(e.to_string()),
                hardware_tpm: false,
            }),
        }
    }
}

/// Attestation binding for proof sealing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBinding {
    /// Quote hash
    pub quote_hash: String,
    /// PCR values at attestation time
    pub pcr_digest: String,
    /// Whether hardware TPM was used
    pub hardware_tpm: bool,
    /// Timestamp
    pub timestamp: i64,
    /// Node ID
    pub node_id: String,
}

impl AttestationBinding {
    /// Create binding from a quote
    pub fn from_quote(quote: &TpmQuote) -> Self {
        // Compute PCR digest
        let mut pcr_h = Sha256::new();
        let mut indices: Vec<_> = quote.pcr_values.keys().collect();
        indices.sort();
        for idx in indices {
            pcr_h.update([*idx]);
            pcr_h.update(quote.pcr_values[idx].as_bytes());
        }
        let pcr_digest = hex::encode(pcr_h.finalize());

        Self {
            quote_hash: quote.hash_hex(),
            pcr_digest,
            hardware_tpm: !quote.simulated,
            timestamp: quote.timestamp,
            node_id: quote.node_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcr_selection_to_string() {
        let sel = PcrSelection::new(PcrBank::Sha256, vec![0, 1, 7]);
        assert_eq!(sel.to_tpm2_string(), "sha256:0,1,7");
    }

    #[test]
    fn test_simulated_quote_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_tpm_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let mut attestor = TpmAttestor::new("test-node", &tmp).unwrap();
        let nonce = b"test-nonce-12345";
        let pcr_sel = PcrSelection::default();

        // Generate simulated quote
        let quote = attestor.generate_simulated_quote(&pcr_sel, nonce).unwrap();

        assert!(quote.simulated);
        assert_eq!(quote.node_id, "test-node");
        assert_eq!(quote.nonce, hex::encode(nonce));
        assert!(!quote.pcr_values.is_empty());

        // Verify quote
        let verified = attestor.verify_quote(&quote, nonce).unwrap();
        assert!(verified);

        // Verify with wrong nonce should fail
        let wrong_nonce = b"wrong-nonce-1234";
        let result = attestor.verify_quote(&quote, wrong_nonce);
        assert!(result.is_err());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_quote_hash_deterministic() {
        let quote1 = TpmQuote {
            quote_id: "q1".to_string(),
            timestamp: 1000,
            node_id: "node1".to_string(),
            pcr_selection: PcrSelection::default(),
            pcr_values: {
                let mut m = HashMap::new();
                m.insert(0, "abc123".to_string());
                m
            },
            nonce: "nonce1".to_string(),
            signature: "sig1".to_string(),
            quote_message: "msg1".to_string(),
            aik_public: "aik1".to_string(),
            simulated: true,
        };

        let quote2 = TpmQuote {
            quote_id: "q1".to_string(),
            timestamp: 1000,
            node_id: "node1".to_string(),
            pcr_selection: PcrSelection::default(),
            pcr_values: {
                let mut m = HashMap::new();
                m.insert(0, "abc123".to_string());
                m
            },
            nonce: "nonce1".to_string(),
            signature: "sig1".to_string(),
            quote_message: "msg1".to_string(),
            aik_public: "aik1".to_string(),
            simulated: true,
        };

        assert_eq!(quote1.compute_hash(), quote2.compute_hash());
    }

    #[test]
    fn test_attestation_binding() {
        let quote = TpmQuote {
            quote_id: "q1".to_string(),
            timestamp: 1000,
            node_id: "node1".to_string(),
            pcr_selection: PcrSelection::default(),
            pcr_values: {
                let mut m = HashMap::new();
                m.insert(0, "abc123".to_string());
                m.insert(1, "def456".to_string());
                m
            },
            nonce: "nonce1".to_string(),
            signature: "sig1".to_string(),
            quote_message: "msg1".to_string(),
            aik_public: "aik1".to_string(),
            simulated: false,
        };

        let binding = AttestationBinding::from_quote(&quote);
        assert_eq!(binding.node_id, "node1");
        assert!(binding.hardware_tpm);
        assert!(!binding.pcr_digest.is_empty());
        assert!(!binding.quote_hash.is_empty());
    }
}
