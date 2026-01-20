//! Offline verification (0.5 / 3.x)
//!
//! This module provides offline verification of exported bundles,
//! ensuring forensic integrity without network access.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub errors: Vec<VerificationError>,
    pub warnings: Vec<String>,
    pub stats: VerificationStats,
}

#[allow(dead_code)]
struct ChainRecordParsed {
    node_id: String,
    hour_ts: i64,
    prev_root_hex: String,
    hour_root: [u8; 32],
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

fn decode_32(hex_s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn compute_chain_hash(prev_hour_root: &str, hour_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ritma-chain-hash@0.1");

    let prev = decode_32(prev_hour_root)
        .unwrap_or_else(|| Sha256::digest(prev_hour_root.as_bytes()).into());
    h.update(prev);
    h.update(hour_root);
    h.finalize().into()
}

fn verify_sig_file(
    sig_path: &Path,
    sig_tag: &str,
    node_id: &str,
    payload32: &[u8; 32],
    pubkeys: &HashMap<String, [u8; 32]>,
    require_signature: bool,
    stats: &mut VerificationStats,
) -> Result<(), VerificationError> {
    if !sig_path.exists() {
        if require_signature {
            return Err(VerificationError::MissingFile(
                sig_path.to_string_lossy().to_string(),
            ));
        }
        return Ok(());
    }

    let data = std::fs::read(sig_path).map_err(|e| VerificationError::CorruptedData {
        file: sig_path.to_string_lossy().to_string(),
        reason: e.to_string(),
    })?;

    stats.bytes_verified += data.len() as u64;

    let v: ciborium::value::Value =
        ciborium::from_reader(&data[..]).map_err(|e| VerificationError::CorruptedData {
            file: sig_path.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(VerificationError::CorruptedData {
            file: sig_path.to_string_lossy().to_string(),
            reason: "not an array".to_string(),
        });
    };

    let Some(ciborium::value::Value::Text(tag)) = arr.get(0) else {
        return Err(VerificationError::CorruptedData {
            file: sig_path.to_string_lossy().to_string(),
            reason: "missing tag".to_string(),
        });
    };
    if tag != "ritma-sig@0.1" {
        return Err(VerificationError::CorruptedData {
            file: sig_path.to_string_lossy().to_string(),
            reason: "unexpected sig tag".to_string(),
        });
    }

    let key_id = match arr.get(1) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => {
            return Err(VerificationError::CorruptedData {
                file: sig_path.to_string_lossy().to_string(),
                reason: "missing key_id".to_string(),
            })
        }
    };
    let alg = match arr.get(2) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => "".to_string(),
    };
    let payload_hex = match arr.get(3) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => "".to_string(),
    };
    let sig_hex = match arr.get(4) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => "".to_string(),
    };

    let expected_payload_hex = hex::encode(payload32);
    if payload_hex != expected_payload_hex {
        return Err(VerificationError::InvalidSignature {
            file: sig_path.to_string_lossy().to_string(),
            reason: "payload hash mismatch".to_string(),
        });
    }

    if alg == "none" || sig_hex.is_empty() {
        if require_signature {
            return Err(VerificationError::InvalidSignature {
                file: sig_path.to_string_lossy().to_string(),
                reason: "missing signature".to_string(),
            });
        }
        return Ok(());
    }

    if alg != "ed25519" {
        if require_signature {
            return Err(VerificationError::InvalidSignature {
                file: sig_path.to_string_lossy().to_string(),
                reason: format!("unsupported signature alg: {alg}"),
            });
        }
        return Ok(());
    }

    let Some(pubkey_bytes) = pubkeys.get(&key_id).copied() else {
        if require_signature {
            return Err(VerificationError::InvalidSignature {
                file: sig_path.to_string_lossy().to_string(),
                reason: "missing public key for key_id".to_string(),
            });
        }
        return Ok(());
    };
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
        VerificationError::InvalidSignature {
            file: sig_path.to_string_lossy().to_string(),
            reason: format!("invalid public key: {e}"),
        }
    })?;

    let sig_raw = hex::decode(&sig_hex).map_err(|e| VerificationError::InvalidSignature {
        file: sig_path.to_string_lossy().to_string(),
        reason: format!("invalid sig hex: {e}"),
    })?;
    if sig_raw.len() != 64 {
        return Err(VerificationError::InvalidSignature {
            file: sig_path.to_string_lossy().to_string(),
            reason: "invalid signature length".to_string(),
        });
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_raw);
    let signature = Signature::from_bytes(&sig_arr);

    let msg = build_signed_msg(sig_tag, node_id, payload32).map_err(|reason| {
        VerificationError::InvalidSignature {
            file: sig_path.to_string_lossy().to_string(),
            reason,
        }
    })?;

    verifying_key
        .verify(&msg, &signature)
        .map_err(|e| VerificationError::InvalidSignature {
            file: sig_path.to_string_lossy().to_string(),
            reason: format!("ed25519 verify failed: {e}"),
        })?;

    stats.signatures_verified += 1;
    Ok(())
}

fn build_signed_msg(sig_tag: &str, node_id: &str, payload32: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut msg: Vec<u8> = Vec::new();
    let tuple = ("ritma-signed@0.1", sig_tag, node_id, hex::encode(payload32));
    ciborium::into_writer(&tuple, &mut msg).map_err(|e| e.to_string())?;
    Ok(msg)
}

fn read_micro_root(
    p: &Path,
    stats: &mut VerificationStats,
) -> Result<(String, Option<[u8; 32]>), VerificationError> {
    let data = std::fs::read(p).map_err(|e| VerificationError::CorruptedData {
        file: p.to_string_lossy().to_string(),
        reason: e.to_string(),
    })?;
    stats.bytes_verified += data.len() as u64;

    let v: ciborium::value::Value =
        ciborium::from_reader(&data[..]).map_err(|e| VerificationError::CorruptedData {
            file: p.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(VerificationError::CorruptedData {
            file: p.to_string_lossy().to_string(),
            reason: "not an array".to_string(),
        });
    };

    let tag = match arr.get(0) {
        Some(ciborium::value::Value::Text(s)) => s.as_str(),
        _ => "",
    };
    if tag != "ritma-micro@0.2" && tag != "ritma-micro@0.1" {
        return Err(VerificationError::CorruptedData {
            file: p.to_string_lossy().to_string(),
            reason: "unexpected micro tag".to_string(),
        });
    }

    let node_id = match arr.get(2) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => "".to_string(),
    };
    if tag == "ritma-micro@0.1" {
        return Ok((node_id, None));
    }

    let root_hex = match arr.get(7) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => {
            return Err(VerificationError::CorruptedData {
                file: p.to_string_lossy().to_string(),
                reason: "missing micro root".to_string(),
            })
        }
    };
    let root = decode_32(&root_hex).ok_or_else(|| VerificationError::CorruptedData {
        file: p.to_string_lossy().to_string(),
        reason: "invalid micro root hex".to_string(),
    })?;

    Ok((node_id, Some(root)))
}

fn read_micro_leaves(
    p: &Path,
    stats: &mut VerificationStats,
) -> Result<Vec<[u8; 32]>, VerificationError> {
    let data = std::fs::read(p).map_err(|e| VerificationError::CorruptedData {
        file: p.to_string_lossy().to_string(),
        reason: e.to_string(),
    })?;
    stats.bytes_verified += data.len() as u64;

    let raw = zstd::decode_all(&data[..]).map_err(|e| VerificationError::CorruptedData {
        file: p.to_string_lossy().to_string(),
        reason: e.to_string(),
    })?;

    let v: ciborium::value::Value =
        ciborium::from_reader(&raw[..]).map_err(|e| VerificationError::CorruptedData {
            file: p.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(VerificationError::CorruptedData {
            file: p.to_string_lossy().to_string(),
            reason: "not an array".to_string(),
        });
    };

    let Some(ciborium::value::Value::Text(tag)) = arr.get(0) else {
        return Err(VerificationError::CorruptedData {
            file: p.to_string_lossy().to_string(),
            reason: "missing tag".to_string(),
        });
    };
    if tag != "ritma-micro-leaves@0.1" {
        return Err(VerificationError::CorruptedData {
            file: p.to_string_lossy().to_string(),
            reason: "unexpected micro leaves tag".to_string(),
        });
    }

    let Some(ciborium::value::Value::Array(leaves)) = arr.get(6) else {
        return Err(VerificationError::CorruptedData {
            file: p.to_string_lossy().to_string(),
            reason: "missing leaves".to_string(),
        });
    };

    let mut out = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        let ciborium::value::Value::Text(hex_s) = leaf else {
            continue;
        };
        if let Some(b) = decode_32(hex_s) {
            out.push(b);
        }
    }
    Ok(out)
}

impl OfflineVerifier {
    fn load_pubkeys(&self) -> Result<HashMap<String, [u8; 32]>, VerificationError> {
        let p = self.bundle_path.join("_meta/keys/pubkeys.cbor");
        if !p.exists() {
            return Err(VerificationError::MissingFile(
                "_meta/keys/pubkeys.cbor".to_string(),
            ));
        }
        let data = std::fs::read(&p).map_err(|e| VerificationError::CorruptedData {
            file: p.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;

        let v: ciborium::value::Value =
            ciborium::from_reader(&data[..]).map_err(|e| VerificationError::CorruptedData {
                file: p.to_string_lossy().to_string(),
                reason: e.to_string(),
            })?;

        let ciborium::value::Value::Array(arr) = v else {
            return Err(VerificationError::CorruptedData {
                file: p.to_string_lossy().to_string(),
                reason: "not an array".to_string(),
            });
        };

        let tag = match arr.get(0) {
            Some(ciborium::value::Value::Text(s)) => s.as_str(),
            _ => "",
        };
        if tag != "ritma-pubkeys@0.2" && tag != "ritma-pubkeys@0.1" {
            return Err(VerificationError::CorruptedData {
                file: p.to_string_lossy().to_string(),
                reason: "unexpected pubkeys tag".to_string(),
            });
        }

        let keys_v = arr.get(3).cloned().unwrap_or(ciborium::value::Value::Null);
        let ciborium::value::Value::Array(keys) = keys_v else {
            return Ok(HashMap::new());
        };

        let mut out: HashMap<String, [u8; 32]> = HashMap::new();
        for k in keys {
            let ciborium::value::Value::Array(karr) = k else {
                continue;
            };
            let key_id = match karr.get(0) {
                Some(ciborium::value::Value::Text(s)) => s.clone(),
                _ => continue,
            };

            let pub_hex_opt = if tag == "ritma-pubkeys@0.2" {
                karr.get(3).and_then(|v| match v {
                    ciborium::value::Value::Text(s) => Some(s.clone()),
                    ciborium::value::Value::Null => None,
                    _ => None,
                })
            } else {
                None
            };

            let Some(pub_hex) = pub_hex_opt else {
                continue;
            };

            let Some(pub_bytes) = decode_32(&pub_hex) else {
                continue;
            };
            out.insert(key_id, pub_bytes);
        }

        Ok(out)
    }
}

impl VerificationResult {
    pub fn success(stats: VerificationStats) -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            stats,
        }
    }

    pub fn failure(errors: Vec<VerificationError>, stats: VerificationStats) -> Self {
        Self {
            valid: false,
            errors,
            warnings: Vec::new(),
            stats,
        }
    }

    pub fn add_warning(&mut self, warning: &str) {
        self.warnings.push(warning.to_string());
    }
}

/// Verification error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationError {
    MissingFile(String),
    HashMismatch {
        file: String,
        expected: String,
        actual: String,
    },
    ChainBreak {
        hour_ts: i64,
        expected_prev: String,
        actual_prev: String,
    },
    InvalidSignature {
        file: String,
        reason: String,
    },
    MerkleRootMismatch {
        level: String,
        expected: String,
        actual: String,
    },
    CorruptedData {
        file: String,
        reason: String,
    },
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFile(path) => write!(f, "missing file: {}", path),
            Self::HashMismatch {
                file,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "hash mismatch in {}: expected {}, got {}",
                    file, expected, actual
                )
            }
            Self::ChainBreak {
                hour_ts,
                expected_prev,
                actual_prev,
            } => {
                write!(
                    f,
                    "chain break at {}: expected prev {}, got {}",
                    hour_ts, expected_prev, actual_prev
                )
            }
            Self::InvalidSignature { file, reason } => {
                write!(f, "invalid signature in {}: {}", file, reason)
            }
            Self::MerkleRootMismatch {
                level,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "merkle root mismatch at {}: expected {}, got {}",
                    level, expected, actual
                )
            }
            Self::CorruptedData { file, reason } => {
                write!(f, "corrupted data in {}: {}", file, reason)
            }
        }
    }
}

/// Verification statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationStats {
    pub hours_verified: u32,
    pub micro_windows_verified: u32,
    pub chain_links_verified: u32,
    pub signatures_verified: u32,
    pub bytes_verified: u64,
}

/// Offline verifier for RITMA_OUT bundles
pub struct OfflineVerifier {
    bundle_path: PathBuf,
}

impl OfflineVerifier {
    pub fn new(bundle_path: &Path) -> Self {
        Self {
            bundle_path: bundle_path.to_path_buf(),
        }
    }

    /// Verify the entire bundle
    pub fn verify_all(&self) -> std::io::Result<VerificationResult> {
        let mut errors = Vec::new();
        let mut stats = VerificationStats::default();

        let require_signature = env_truthy("RITMA_VERIFY_REQUIRE_SIGNATURE")
            || env_truthy("RITMA_OUT_REQUIRE_SIGNATURE");
        let require_tpm =
            env_truthy("RITMA_VERIFY_REQUIRE_TPM") || env_truthy("RITMA_OUT_REQUIRE_TPM");

        let pubkeys = match self.load_pubkeys() {
            Ok(m) => m,
            Err(e) => {
                if require_signature {
                    errors.push(e);
                }
                HashMap::new()
            }
        };

        // Verify _meta/store.cbor exists
        let store_meta = self.bundle_path.join("_meta/store.cbor");
        if !store_meta.exists() {
            errors.push(VerificationError::MissingFile(
                "_meta/store.cbor".to_string(),
            ));
        }

        // Verify chain integrity
        if let Err(chain_errors) =
            self.verify_chain(&pubkeys, require_signature, require_tpm, &mut stats)
        {
            errors.extend(chain_errors);
        }

        // Verify hour proofs
        if let Err(hour_errors) = self.verify_hours(&pubkeys, require_signature, &mut stats) {
            errors.extend(hour_errors);
        }

        if errors.is_empty() {
            Ok(VerificationResult::success(stats))
        } else {
            Ok(VerificationResult::failure(errors, stats))
        }
    }

    /// Verify chain integrity (prev_root chaining)
    fn verify_chain(
        &self,
        pubkeys: &HashMap<String, [u8; 32]>,
        require_signature: bool,
        require_tpm: bool,
        stats: &mut VerificationStats,
    ) -> Result<(), Vec<VerificationError>> {
        let mut errors = Vec::new();
        let windows_dir = self.bundle_path.join("windows");

        if !windows_dir.exists() {
            return Ok(()); // No windows to verify
        }

        let mut prev_hour_root: Option<[u8; 32]> = None;
        let mut hours = self.collect_hour_dirs(&windows_dir)?;
        hours.sort();

        for hour_dir in hours {
            let chain_file = hour_dir.join("proofs/chain.cbor");
            if !chain_file.exists() {
                continue;
            }

            match self.verify_chain_record(&chain_file, prev_hour_root, stats) {
                Ok(rec) => {
                    let chain_hash = compute_chain_hash(&rec.prev_root_hex, &rec.hour_root);

                    let chain_sig = hour_dir.join("proofs/chain.sig");
                    if let Err(e) = verify_sig_file(
                        &chain_sig,
                        "ritma-chain-sig@0.1",
                        &rec.node_id,
                        &chain_hash,
                        pubkeys,
                        require_signature,
                        stats,
                    ) {
                        errors.push(e);
                    }

                    if let Err(e) =
                        self.verify_tpm(&hour_dir.join("proofs"), &chain_hash, require_tpm)
                    {
                        errors.push(e);
                    }

                    prev_hour_root = Some(rec.hour_root);
                    stats.chain_links_verified += 1;
                }
                Err(e) => errors.push(e),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn verify_chain_record(
        &self,
        chain_file: &Path,
        expected_prev: Option<[u8; 32]>,
        stats: &mut VerificationStats,
    ) -> Result<ChainRecordParsed, VerificationError> {
        let data = std::fs::read(chain_file).map_err(|e| VerificationError::CorruptedData {
            file: chain_file.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;

        stats.bytes_verified += data.len() as u64;

        let v: ciborium::value::Value =
            ciborium::from_reader(&data[..]).map_err(|e| VerificationError::CorruptedData {
                file: chain_file.to_string_lossy().to_string(),
                reason: e.to_string(),
            })?;

        let ciborium::value::Value::Array(arr) = v else {
            return Err(VerificationError::CorruptedData {
                file: chain_file.to_string_lossy().to_string(),
                reason: "not an array".to_string(),
            });
        };

        let node_id = match arr.get(1) {
            Some(ciborium::value::Value::Text(s)) => s.clone(),
            _ => "".to_string(),
        };

        // Parse prev_root and hour_root
        let prev_root_hex = match arr.get(3) {
            Some(ciborium::value::Value::Text(s)) => s.clone(),
            _ => {
                return Err(VerificationError::CorruptedData {
                    file: chain_file.to_string_lossy().to_string(),
                    reason: "missing prev_root".to_string(),
                })
            }
        };

        let hour_root_hex = match arr.get(4) {
            Some(ciborium::value::Value::Text(s)) => s.clone(),
            _ => {
                return Err(VerificationError::CorruptedData {
                    file: chain_file.to_string_lossy().to_string(),
                    reason: "missing hour_root".to_string(),
                })
            }
        };

        let hour_ts = match arr.get(2) {
            Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0i64),
            _ => 0,
        };

        // Verify prev_root matches expected
        if let Some(expected) = expected_prev {
            let expected_hex = hex::encode(expected);
            if prev_root_hex != expected_hex {
                return Err(VerificationError::ChainBreak {
                    hour_ts,
                    expected_prev: expected_hex,
                    actual_prev: prev_root_hex,
                });
            }
        }

        // Return hour_root for next iteration
        let hour_root = hex::decode(&hour_root_hex)
            .ok()
            .and_then(|b| {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    Some(arr)
                } else {
                    None
                }
            })
            .ok_or_else(|| VerificationError::CorruptedData {
                file: chain_file.to_string_lossy().to_string(),
                reason: "invalid hour_root hex".to_string(),
            })?;

        if let Some(ciborium::value::Value::Text(chain_hash_hex)) = arr.get(5) {
            let computed = compute_chain_hash(&prev_root_hex, &hour_root);
            let computed_hex = hex::encode(computed);
            if chain_hash_hex != &computed_hex {
                return Err(VerificationError::HashMismatch {
                    file: chain_file.to_string_lossy().to_string(),
                    expected: chain_hash_hex.clone(),
                    actual: computed_hex,
                });
            }
        }

        Ok(ChainRecordParsed {
            node_id,
            hour_ts,
            prev_root_hex,
            hour_root,
        })
    }

    /// Verify hour proofs (micro roots -> hour root)
    fn verify_hours(
        &self,
        pubkeys: &HashMap<String, [u8; 32]>,
        require_signature: bool,
        stats: &mut VerificationStats,
    ) -> Result<(), Vec<VerificationError>> {
        let mut errors = Vec::new();
        let windows_dir = self.bundle_path.join("windows");

        if !windows_dir.exists() {
            return Ok(());
        }

        let hours = self.collect_hour_dirs(&windows_dir)?;

        for hour_dir in hours {
            match self.verify_hour(&hour_dir, pubkeys, require_signature, stats) {
                Ok(()) => stats.hours_verified += 1,
                Err(e) => errors.push(e),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn verify_hour(
        &self,
        hour_dir: &Path,
        pubkeys: &HashMap<String, [u8; 32]>,
        require_signature: bool,
        stats: &mut VerificationStats,
    ) -> Result<(), VerificationError> {
        let hour_root_file = hour_dir.join("proofs/hour_root.cbor");
        if !hour_root_file.exists() {
            return Ok(()); // No proof to verify
        }

        // Read hour_root.cbor
        let data =
            std::fs::read(&hour_root_file).map_err(|e| VerificationError::CorruptedData {
                file: hour_root_file.to_string_lossy().to_string(),
                reason: e.to_string(),
            })?;

        stats.bytes_verified += data.len() as u64;

        let v: ciborium::value::Value =
            ciborium::from_reader(&data[..]).map_err(|e| VerificationError::CorruptedData {
                file: hour_root_file.to_string_lossy().to_string(),
                reason: e.to_string(),
            })?;

        let ciborium::value::Value::Array(arr) = v else {
            return Err(VerificationError::CorruptedData {
                file: hour_root_file.to_string_lossy().to_string(),
                reason: "not an array".to_string(),
            });
        };

        let hour_node_id = match arr.get(1) {
            Some(ciborium::value::Value::Text(s)) => s.clone(),
            _ => "".to_string(),
        };

        // Get claimed hour_root
        let claimed_root_hex = match arr.get(3) {
            Some(ciborium::value::Value::Text(s)) => s.clone(),
            _ => {
                return Err(VerificationError::CorruptedData {
                    file: hour_root_file.to_string_lossy().to_string(),
                    reason: "missing hour_root".to_string(),
                })
            }
        };

        let mut micro_roots_hex: Vec<String> = match arr.get(4) {
            Some(ciborium::value::Value::Array(roots)) => roots
                .iter()
                .filter_map(|r| {
                    if let ciborium::value::Value::Text(s) = r {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => Vec::new(),
        };

        let micro_scan = self.verify_micro_windows(hour_dir, pubkeys, require_signature, stats)?;
        if micro_roots_hex.is_empty() {
            micro_roots_hex = micro_scan
                .iter()
                .map(|r| hex::encode(r))
                .collect::<Vec<String>>();
        } else if micro_scan
            .iter()
            .map(|r| hex::encode(r))
            .collect::<Vec<String>>()
            != micro_roots_hex
        {
            return Err(VerificationError::CorruptedData {
                file: hour_root_file.to_string_lossy().to_string(),
                reason: "micro roots list does not match micro files".to_string(),
            });
        }

        let micro_roots: Vec<[u8; 32]> = micro_roots_hex
            .iter()
            .filter_map(|h| decode_32(h))
            .collect();

        let computed_root = merkle_root_sha256(&micro_roots);
        let computed_root_hex = hex::encode(computed_root);

        if computed_root_hex != claimed_root_hex {
            return Err(VerificationError::MerkleRootMismatch {
                level: "hour".to_string(),
                expected: claimed_root_hex,
                actual: computed_root_hex,
            });
        }

        let hour_sig = hour_dir.join("proofs/hour_root.sig");
        let _ = verify_sig_file(
            &hour_sig,
            "ritma-hour-root-sig@0.1",
            &hour_node_id,
            &computed_root,
            pubkeys,
            require_signature,
            stats,
        )?;

        stats.micro_windows_verified += micro_roots.len() as u32;
        Ok(())
    }

    fn verify_micro_windows(
        &self,
        hour_dir: &Path,
        pubkeys: &HashMap<String, [u8; 32]>,
        require_signature: bool,
        stats: &mut VerificationStats,
    ) -> Result<Vec<[u8; 32]>, VerificationError> {
        let micro_dir = hour_dir.join("micro");
        let rd = match std::fs::read_dir(&micro_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(VerificationError::CorruptedData {
                    file: micro_dir.to_string_lossy().to_string(),
                    reason: e.to_string(),
                })
            }
        };

        let mut micro_files: Vec<PathBuf> = rd
            .flatten()
            .filter_map(|e| {
                if e.file_type().ok().map(|t| t.is_file()).unwrap_or(false) {
                    Some(e.path())
                } else {
                    None
                }
            })
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("cbor"))
            .collect();
        micro_files.sort();

        let mut out: Vec<[u8; 32]> = Vec::new();
        for p in micro_files {
            let Some(stem) = p
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
            else {
                continue;
            };
            if stem.ends_with(".leaves") {
                continue;
            }

            let (node_id, claimed_root_opt) = read_micro_root(&p, stats)?;
            let Some(claimed_root) = claimed_root_opt else {
                continue;
            };

            let leaves_path = micro_dir.join(format!("{stem}.leaves.cbor.zst"));
            if leaves_path.exists() {
                let leaves = read_micro_leaves(&leaves_path, stats)?;
                let computed = merkle_root_sha256(&leaves);
                if computed != claimed_root {
                    return Err(VerificationError::MerkleRootMismatch {
                        level: "micro".to_string(),
                        expected: hex::encode(claimed_root),
                        actual: hex::encode(computed),
                    });
                }
            }

            let sig_path = micro_dir.join(format!("{stem}.sig"));
            let _ = verify_sig_file(
                &sig_path,
                "ritma-micro-sig@0.1",
                &node_id,
                &claimed_root,
                pubkeys,
                require_signature,
                stats,
            )?;

            out.push(claimed_root);
        }

        Ok(out)
    }

    fn verify_tpm(
        &self,
        proofs_dir: &Path,
        chain_hash: &[u8; 32],
        require_tpm: bool,
    ) -> Result<(), VerificationError> {
        let quote_path = proofs_dir.join("tpm_quote.cbor");
        let binding_path = proofs_dir.join("tpm_binding.cbor");

        if !quote_path.exists() || !binding_path.exists() {
            if require_tpm {
                if !quote_path.exists() {
                    return Err(VerificationError::MissingFile(
                        quote_path.to_string_lossy().to_string(),
                    ));
                }
                if !binding_path.exists() {
                    return Err(VerificationError::MissingFile(
                        binding_path.to_string_lossy().to_string(),
                    ));
                }
            }
            return Ok(());
        }

        let quote_bytes =
            std::fs::read(&quote_path).map_err(|e| VerificationError::CorruptedData {
                file: quote_path.to_string_lossy().to_string(),
                reason: e.to_string(),
            })?;

        let quote: node_keystore::TpmQuote =
            ciborium::from_reader(&quote_bytes[..]).map_err(|e| {
                VerificationError::CorruptedData {
                    file: quote_path.to_string_lossy().to_string(),
                    reason: e.to_string(),
                }
            })?;

        let binding_bytes =
            std::fs::read(&binding_path).map_err(|e| VerificationError::CorruptedData {
                file: binding_path.to_string_lossy().to_string(),
                reason: e.to_string(),
            })?;

        let binding_v: ciborium::value::Value =
            ciborium::from_reader(&binding_bytes[..]).map_err(|e| {
                VerificationError::CorruptedData {
                    file: binding_path.to_string_lossy().to_string(),
                    reason: e.to_string(),
                }
            })?;

        let ciborium::value::Value::Array(binding_arr) = binding_v else {
            return Err(VerificationError::CorruptedData {
                file: binding_path.to_string_lossy().to_string(),
                reason: "not an array".to_string(),
            });
        };

        let Some(ciborium::value::Value::Text(binding_tag)) = binding_arr.get(0) else {
            return Err(VerificationError::CorruptedData {
                file: binding_path.to_string_lossy().to_string(),
                reason: "missing tag".to_string(),
            });
        };
        if binding_tag != "ritma-tpm-binding@0.1" {
            return Err(VerificationError::CorruptedData {
                file: binding_path.to_string_lossy().to_string(),
                reason: "unexpected tpm binding tag".to_string(),
            });
        }

        let expected_binding = node_keystore::AttestationBinding::from_quote(&quote);
        let expected_tuple = (
            expected_binding.quote_hash,
            expected_binding.pcr_digest,
            expected_binding.hardware_tpm,
            expected_binding.timestamp,
            expected_binding.node_id,
        );

        let actual_tuple = (
            binding_arr
                .get(1)
                .and_then(|v| match v {
                    ciborium::value::Value::Text(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_default(),
            binding_arr
                .get(2)
                .and_then(|v| match v {
                    ciborium::value::Value::Text(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_default(),
            binding_arr
                .get(3)
                .and_then(|v| match v {
                    ciborium::value::Value::Bool(b) => Some(*b),
                    _ => None,
                })
                .unwrap_or(false),
            binding_arr
                .get(4)
                .and_then(|v| match v {
                    ciborium::value::Value::Integer(i) => (*i).try_into().ok(),
                    _ => None,
                })
                .unwrap_or(0i64),
            binding_arr
                .get(5)
                .and_then(|v| match v {
                    ciborium::value::Value::Text(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_default(),
        );

        if expected_tuple != actual_tuple {
            return Err(VerificationError::CorruptedData {
                file: binding_path.to_string_lossy().to_string(),
                reason: "tpm binding does not match quote".to_string(),
            });
        }

        let expected_nonce: [u8; 32] = Sha256::digest(chain_hash).into();
        let attestor = node_keystore::TpmAttestor::from_env().map_err(|e| {
            VerificationError::InvalidSignature {
                file: quote_path.to_string_lossy().to_string(),
                reason: e.to_string(),
            }
        })?;

        attestor
            .verify_quote(&quote, &expected_nonce)
            .map_err(|e| VerificationError::InvalidSignature {
                file: quote_path.to_string_lossy().to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    fn collect_hour_dirs(
        &self,
        windows_dir: &Path,
    ) -> Result<Vec<PathBuf>, Vec<VerificationError>> {
        let mut hours = Vec::new();
        self.scan_years(windows_dir, &mut hours);
        Ok(hours)
    }

    fn scan_years(&self, windows_dir: &Path, hours: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(windows_dir) {
            Ok(r) => r,
            Err(_) => return,
        };

        for year in rd.flatten() {
            if year.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                self.scan_months(&year.path(), hours);
            }
        }
    }

    fn scan_months(&self, year_dir: &Path, hours: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(year_dir) {
            Ok(r) => r,
            Err(_) => return,
        };

        for month in rd.flatten() {
            if month.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                self.scan_days(&month.path(), hours);
            }
        }
    }

    fn scan_days(&self, month_dir: &Path, hours: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(month_dir) {
            Ok(r) => r,
            Err(_) => return,
        };

        for day in rd.flatten() {
            if day.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                self.scan_hours(&day.path(), hours);
            }
        }
    }

    fn scan_hours(&self, day_dir: &Path, hours: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(day_dir) {
            Ok(r) => r,
            Err(_) => return,
        };

        for hour in rd.flatten() {
            if hour.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                hours.push(hour.path());
            }
        }
    }
}

/// Compute Merkle root over SHA256 hashes
fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        let mut h = Sha256::new();
        h.update(b"ritma-merkle-empty@0.1");
        return h.finalize().into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };

            let mut h = Sha256::new();
            h.update(b"ritma-merkle-node@0.1");
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());

            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Export bundle creator
pub struct BundleExporter {
    source_dir: PathBuf,
}

impl BundleExporter {
    pub fn new(source_dir: &Path) -> Self {
        Self {
            source_dir: source_dir.to_path_buf(),
        }
    }

    /// Export a time range to a standalone bundle
    pub fn export_range(
        &self,
        output_dir: &Path,
        start_ts: i64,
        end_ts: i64,
    ) -> std::io::Result<ExportResult> {
        std::fs::create_dir_all(output_dir)?;

        let mut result = ExportResult {
            bundle_path: output_dir.to_path_buf(),
            hours_exported: 0,
            bytes_exported: 0,
            start_ts,
            end_ts,
        };

        // Copy _meta
        let meta_src = self.source_dir.join("_meta");
        let meta_dst = output_dir.join("_meta");
        if meta_src.exists() {
            self.copy_dir_recursive(&meta_src, &meta_dst, &mut result.bytes_exported)?;
        }

        // Copy relevant windows
        let windows_src = self.source_dir.join("windows");
        let windows_dst = output_dir.join("windows");
        if windows_src.exists() {
            self.copy_windows_in_range(&windows_src, &windows_dst, start_ts, end_ts, &mut result)?;
        }

        // Copy relevant catalog entries
        let catalog_src = self.source_dir.join("catalog");
        let catalog_dst = output_dir.join("catalog");
        if catalog_src.exists() {
            self.copy_catalog_in_range(
                &catalog_src,
                &catalog_dst,
                start_ts,
                end_ts,
                &mut result.bytes_exported,
            )?;
        }

        // Write export manifest
        self.write_export_manifest(output_dir, &result)?;

        Ok(result)
    }

    fn copy_dir_recursive(&self, src: &Path, dst: &Path, bytes: &mut u64) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)?.flatten() {
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if entry.file_type()?.is_dir() {
                self.copy_dir_recursive(&src_path, &dst_path, bytes)?;
            } else {
                let data = std::fs::read(&src_path)?;
                *bytes += data.len() as u64;
                std::fs::write(&dst_path, data)?;
            }
        }
        Ok(())
    }

    fn copy_windows_in_range(
        &self,
        src: &Path,
        dst: &Path,
        start_ts: i64,
        end_ts: i64,
        result: &mut ExportResult,
    ) -> std::io::Result<()> {
        // Iterate year/month/day/hour structure
        for year in std::fs::read_dir(src)?.flatten() {
            if !year.file_type()?.is_dir() {
                continue;
            }
            for month in std::fs::read_dir(year.path())?.flatten() {
                if !month.file_type()?.is_dir() {
                    continue;
                }
                for day in std::fs::read_dir(month.path())?.flatten() {
                    if !day.file_type()?.is_dir() {
                        continue;
                    }
                    for hour in std::fs::read_dir(day.path())?.flatten() {
                        if !hour.file_type()?.is_dir() {
                            continue;
                        }

                        // Parse hour timestamp from path
                        let hour_ts = self.parse_hour_ts(&hour.path());
                        let hour_end = hour_ts + 3600;

                        // Check if hour overlaps with range
                        if hour_ts < end_ts && hour_end > start_ts {
                            let hour_path = hour.path();
                            let rel_path = hour_path.strip_prefix(src).unwrap();
                            let dst_hour = dst.join(rel_path);
                            self.copy_dir_recursive(
                                &hour.path(),
                                &dst_hour,
                                &mut result.bytes_exported,
                            )?;
                            result.hours_exported += 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn copy_catalog_in_range(
        &self,
        src: &Path,
        dst: &Path,
        start_ts: i64,
        end_ts: i64,
        bytes: &mut u64,
    ) -> std::io::Result<()> {
        let start_date = chrono::DateTime::from_timestamp(start_ts, 0)
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        let end_date = chrono::DateTime::from_timestamp(end_ts, 0)
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default();

        for year in std::fs::read_dir(src)?.flatten() {
            if !year.file_type()?.is_dir() {
                continue;
            }
            for month in std::fs::read_dir(year.path())?.flatten() {
                if !month.file_type()?.is_dir() {
                    continue;
                }
                for day in std::fs::read_dir(month.path())?.flatten() {
                    if !day.file_type()?.is_dir() {
                        continue;
                    }

                    let date = format!(
                        "{}-{}-{}",
                        year.file_name().to_string_lossy(),
                        month.file_name().to_string_lossy(),
                        day.file_name().to_string_lossy()
                    );

                    if date >= start_date && date <= end_date {
                        let day_path = day.path();
                        let rel_path = day_path.strip_prefix(src).unwrap();
                        let dst_day = dst.join(rel_path);
                        self.copy_dir_recursive(&day.path(), &dst_day, bytes)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_hour_ts(&self, hour_dir: &Path) -> i64 {
        // Path: .../YYYY/MM/DD/HH
        let components: Vec<_> = hour_dir.components().rev().take(4).collect();
        if components.len() < 4 {
            return 0;
        }

        let hour: u32 = components[0]
            .as_os_str()
            .to_string_lossy()
            .parse()
            .unwrap_or(0);
        let day: u32 = components[1]
            .as_os_str()
            .to_string_lossy()
            .parse()
            .unwrap_or(1);
        let month: u32 = components[2]
            .as_os_str()
            .to_string_lossy()
            .parse()
            .unwrap_or(1);
        let year: i32 = components[3]
            .as_os_str()
            .to_string_lossy()
            .parse()
            .unwrap_or(2024);

        chrono::NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|d| d.and_hms_opt(hour, 0, 0))
            .map(|dt| dt.and_utc().timestamp())
            .unwrap_or(0)
    }

    fn write_export_manifest(
        &self,
        output_dir: &Path,
        result: &ExportResult,
    ) -> std::io::Result<()> {
        let manifest = (
            "ritma-export-manifest@0.1",
            result.start_ts,
            result.end_ts,
            result.hours_exported,
            result.bytes_exported,
            chrono::Utc::now().timestamp(),
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&manifest, &mut buf).map_err(std::io::Error::other)?;
        std::fs::write(output_dir.join("export_manifest.cbor"), buf)?;

        Ok(())
    }
}

/// Export result
#[derive(Debug, Clone)]
pub struct ExportResult {
    pub bundle_path: PathBuf,
    pub hours_exported: u32,
    pub bytes_exported: u64,
    pub start_ts: i64,
    pub end_ts: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_result_success() {
        let stats = VerificationStats {
            hours_verified: 24,
            micro_windows_verified: 100,
            chain_links_verified: 24,
            signatures_verified: 0,
            bytes_verified: 1_000_000,
        };
        let result = VerificationResult::success(stats);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn verification_error_display() {
        let err = VerificationError::HashMismatch {
            file: "test.cbor".to_string(),
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("hash mismatch"));
        assert!(msg.contains("test.cbor"));
    }

    #[test]
    fn merkle_root_empty() {
        let root = merkle_root_sha256(&[]);
        assert!(!root.iter().all(|&b| b == 0));
    }

    #[test]
    fn merkle_root_single() {
        let leaf: [u8; 32] = Sha256::digest(b"test").into();
        let root = merkle_root_sha256(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_root_multiple() {
        let leaves: Vec<[u8; 32]> = vec![
            Sha256::digest(b"a").into(),
            Sha256::digest(b"b").into(),
            Sha256::digest(b"c").into(),
        ];
        let root = merkle_root_sha256(&leaves);
        assert!(!root.iter().all(|&b| b == 0));
    }
}
