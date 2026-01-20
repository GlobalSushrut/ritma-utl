# Execution-Entropy Consensus (EEC) Specification

**Version:** 0.1  
**Status:** Draft  
**Last Updated:** 2026-01-19

## Abstract

Execution-Entropy Consensus (EEC) is a constraint-survival model for forensic audit logs. It ensures that recorded execution traces are **admissible** as evidence by enforcing five orthogonal constraints: temporal, causal, cryptographic, observational, and entropic. This document specifies the EEC model, maps constraints to Ritma ProofPack artifacts, and provides citations to foundational research.

---

## 1. Introduction

Traditional audit logs suffer from:
- **Tampering**: Logs can be modified after the fact.
- **Repudiation**: Actors can deny actions.
- **Clock manipulation**: Timestamps can be forged.
- **Selective omission**: Events can be dropped without detection.

EEC addresses these by requiring that every recorded artifact **survives** a set of verifiable constraints. If any constraint fails, the artifact is inadmissible.

### 1.1 Design Goals

1. **Offline verifiability**: No network access required for verification.
2. **Hardware-backed trust**: Optional TPM attestation for observational/entropic constraints.
3. **Incremental sealing**: Proofs generated per micro-window (≤60s) and aggregated hourly.
4. **Backward compatibility**: Older bundles without signatures/TPM remain verifiable (with warnings).

---

## 2. The Five EEC Constraints

### 2.1 Temporal Constraint

**Definition**: Events must be ordered by a monotonic, tamper-evident clock.

**Implementation**:
- Each micro-window has `start_ts` and `end_ts` (Unix epoch, nanoseconds).
- Hour roots aggregate micro-windows in chronological order.
- Chain records link hours with `prev_root` forming a hash chain.

**Verification**:
- `OfflineVerifier::verify_chain()` checks `prev_root` linkage.
- Timestamps must be monotonically increasing within and across windows.

**Citations**:
- Haber, S., & Stornetta, W. S. (1991). "How to Time-Stamp a Digital Document." *Journal of Cryptology*.
- RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP).

### 2.2 Causal Constraint

**Definition**: Events must preserve causal ordering (happens-before relationships).

**Implementation**:
- Micro-window Merkle trees preserve leaf order.
- Hour root is computed from ordered micro-roots.
- Chain hash includes previous hour root, enforcing causal dependency.

**Verification**:
- `OfflineVerifier::verify_hours()` recomputes hour root from micro-roots.
- `merkle_root_sha256()` preserves insertion order.

**Citations**:
- Lamport, L. (1978). "Time, Clocks, and the Ordering of Events in a Distributed System." *Communications of the ACM*.

### 2.3 Cryptographic Constraint

**Definition**: All artifacts must be cryptographically bound to their contents.

**Implementation**:
- **Micro-window**: `micro_root` = Merkle root of leaf hashes (SHA-256).
- **Hour root**: `hour_root` = Merkle root of micro-roots.
- **Chain hash**: `chain_hash = SHA256("ritma-chain-hash@0.1" || prev_root || hour_root)`.
- **Signatures**: Ed25519 signatures on micro, hour, and chain artifacts.

**Artifacts**:
| File | Tag | Signed Payload |
|------|-----|----------------|
| `micro/*.sig` | `ritma-micro-sig@0.1` | `micro_root` |
| `proofs/hour_root.sig` | `ritma-hour-root-sig@0.1` | `hour_root` |
| `proofs/chain.sig` | `ritma-chain-sig@0.1` | `chain_hash` |

**Verification**:
- `verify_sig_file()` loads public keys from `_meta/keys/pubkeys.cbor`.
- Signature format: `("ritma-sig@0.1", key_id, alg, payload_hex, sig_hex)`.

**Citations**:
- Bernstein, D. J., et al. (2012). "High-speed high-security signatures." *Journal of Cryptographic Engineering*.
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA).

### 2.4 Observational Constraint

**Definition**: The recording environment must be attested by a trusted observer.

**Implementation**:
- TPM 2.0 quote binds the chain hash to platform state (PCR values).
- `tpm_quote.cbor`: Contains PCR selection, nonce (chain hash), signature, AIK public key.
- `tpm_binding.cbor`: Links quote hash to chain hash with timestamp.

**Verification**:
- `OfflineVerifier::verify_tpm_binding()` checks:
  - Quote nonce matches chain hash.
  - PCR digest is consistent.
  - Signature verifies against AIK.

**Citations**:
- Trusted Computing Group. (2019). "TPM 2.0 Library Specification."
- Parno, B., et al. (2010). "Bootstrapping Trust in Commodity Computers." *IEEE S&P*.

### 2.5 Entropic Constraint

**Definition**: Artifacts must contain sufficient entropy to prevent pre-computation attacks.

**Implementation**:
- Leaf hashes include event-specific data (timestamps, PIDs, hashes of binaries).
- TPM nonce is derived from chain hash (unpredictable without prior events).
- Micro-window IDs include nanosecond timestamps.

**Verification**:
- Implicit: If cryptographic and observational constraints pass, entropic constraint is satisfied.
- Future: Entropy estimation on leaf data distributions.

**Citations**:
- Dodis, Y., et al. (2004). "On the (Im)possibility of Cryptography with Imperfect Randomness." *FOCS*.

---

## 3. Artifact Schema

### 3.1 Micro-Window (`ritma-micro@0.2`)

```
(
  "ritma-micro@0.2",   // tag
  window_id,           // string: YYYYMMDD_HHMMSS_nnnnnnnnn
  node_id,             // string
  start_ts,            // i64: Unix epoch ns
  end_ts,              // i64: Unix epoch ns
  event_count,         // u64
  leaf_count,          // u64
  micro_root_hex       // string: 64 hex chars (SHA-256)
)
```

### 3.2 Micro Leaves Sidecar (`ritma-micro-leaves@0.1`)

```
(
  "ritma-micro-leaves@0.1",  // tag
  window_id,                  // string
  [leaf_hex, ...]             // array of 64-char hex strings
)
```

Stored as `micro/{window_id}.leaves.cbor.zst` (zstd compressed).

### 3.3 Hour Root (`ritma-hour-root@0.2`)

```
(
  "ritma-hour-root@0.2",  // tag
  node_id,                 // string
  hour_ts,                 // i64: Unix epoch (hour start)
  hour_root_hex,           // string: 64 hex chars
  [micro_root_hex, ...]    // array of micro roots in order
)
```

### 3.4 Chain Record (`ritma-chain@0.3`)

```
(
  "ritma-chain@0.3",   // tag
  node_id,              // string
  hour_ts,              // i64
  prev_root_hex,        // string: 64 hex chars (or GENESIS hash)
  hour_root_hex,        // string: 64 hex chars
  chain_hash_hex        // string: 64 hex chars
)
```

### 3.5 Signature File (`ritma-sig@0.1`)

```
(
  "ritma-sig@0.1",     // tag
  key_id,               // string: key identifier
  alg,                  // string: "ed25519" or "none"
  payload_hex,          // string: 64 hex chars (what was signed)
  sig_hex               // string: 128 hex chars (Ed25519 signature)
)
```

### 3.6 Public Keys (`ritma-pubkeys@0.2`)

```
(
  "ritma-pubkeys@0.2",  // tag
  node_id,               // string
  [
    {
      "key_id": string,
      "algorithm": string,
      "public_key_hash": string,  // SHA-256 of public key
      "ed25519_pubkey": string    // 64 hex chars (32 bytes)
    },
    ...
  ]
)
```

### 3.7 TPM Quote (`ritma-tpm-quote@0.1`)

```
{
  "version": "ritma-tpm-quote@0.1",
  "pcr_selection": { "hash_alg": "sha256", "pcrs": [0, 1, 2, ...] },
  "pcr_digest": string,      // hex
  "nonce": string,           // hex (should match chain_hash)
  "signature": string,       // hex
  "aik_public": string,      // hex (AIK public key)
  "is_hardware": bool,
  "timestamp": i64
}
```

### 3.8 TPM Binding (`ritma-tpm-binding@0.1`)

```
{
  "version": "ritma-tpm-binding@0.1",
  "quote_hash": string,      // SHA-256 of serialized quote
  "pcr_digest": string,
  "is_hardware": bool,
  "timestamp": i64,
  "node_id": string
}
```

---

## 4. Verification Flow

```
OfflineVerifier::verify_all()
├── load_pubkeys()                    // _meta/keys/pubkeys.cbor
├── verify_chain()                    // chain.cbor linkage
│   ├── for each hour:
│   │   ├── verify_chain_record()     // prev_root, chain_hash
│   │   ├── verify_sig_file(chain.sig)
│   │   └── verify_tpm_binding()      // optional
├── verify_hours()                    // hour_root.cbor
│   ├── for each hour:
│   │   ├── verify_hour_root()        // recompute from micro_roots
│   │   ├── verify_sig_file(hour_root.sig)
│   │   └── verify_micro_windows()
│   │       ├── for each micro:
│   │       │   ├── read_micro_root()
│   │       │   ├── read_micro_leaves()
│   │       │   ├── merkle_root_sha256(leaves) == claimed_root
│   │       │   └── verify_sig_file(micro.sig)
└── aggregate stats and errors
```

---

## 5. Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RITMA_OUT_REQUIRE_SIGNATURE` | `false` | Fail sealing if signing unavailable |
| `RITMA_VERIFY_REQUIRE_SIGNATURE` | `false` | Fail verification if signatures missing/invalid |
| `RITMA_OUT_REQUIRE_TPM` | `false` | Fail sealing if TPM unavailable |
| `RITMA_VERIFY_REQUIRE_TPM` | `false` | Fail verification if TPM binding missing/invalid |
| `RITMA_SIGNING_KEY_ID` | (auto) | Key ID to use for signing |

---

## 6. Code Mapping

| Constraint | Sealing Code | Verification Code |
|------------|--------------|-------------------|
| Temporal | `StorageContract::write_micro_window_proof()` | `OfflineVerifier::verify_chain()` |
| Causal | `compute_hour_root_from_micro()` | `OfflineVerifier::verify_hours()` |
| Cryptographic | `write_sig_file()`, `merkle_root_sha256()` | `verify_sig_file()`, `merkle_root_sha256()` |
| Observational | `TpmAttestor::attest()` | `OfflineVerifier::verify_tpm_binding()` |
| Entropic | `canonical_leaf_hash()` | (implicit) |

**Key Files**:
- `crates/ritma_contract/src/lib.rs`: Sealing pipeline, signature generation.
- `crates/ritma_contract/src/verify.rs`: `OfflineVerifier` implementation.
- `crates/node_keystore/src/lib.rs`: Key management, `sign_bytes()`.
- `crates/node_keystore/src/tpm.rs`: TPM attestation.
- `crates/ritma_cli/src/main.rs`: `cmd_verify_proof()`, `cmd_verify_ritma_out_bundle()`.

---

## 7. Security Considerations

### 7.1 Key Management
- Ed25519 private keys are stored in `node_keystore` with zeroization on drop.
- Public keys exported to `_meta/keys/pubkeys.cbor` for offline verification.
- Key rotation: New keys can be added; old signatures remain valid.

### 7.2 TPM Trust
- Hardware TPM provides strongest guarantees.
- Simulated TPM (swtpm) acceptable for development/testing only.
- `is_hardware` flag in binding distinguishes trust levels.

### 7.3 Replay Attacks
- Chain hash includes previous hour root, preventing insertion.
- TPM nonce is chain hash, binding quote to specific chain state.

### 7.4 Clock Attacks
- Monotonic timestamps enforced within node.
- Cross-node synchronization requires external trusted time (RFC 3161 TSR).

---

## 8. Future Work

1. **Witness cosigning**: Multiple nodes sign the same chain hash (threshold signatures).
2. **Certificate Transparency integration**: Publish chain hashes to CT logs.
3. **Entropy estimation**: Statistical tests on leaf data distributions.
4. **Formal verification**: Prove constraint satisfaction in Coq/Lean.

---

## References

1. Haber, S., & Stornetta, W. S. (1991). "How to Time-Stamp a Digital Document." *Journal of Cryptology*, 3(2), 99-111.
2. Lamport, L. (1978). "Time, Clocks, and the Ordering of Events in a Distributed System." *Communications of the ACM*, 21(7), 558-565.
3. Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B. Y. (2012). "High-speed high-security signatures." *Journal of Cryptographic Engineering*, 2(2), 77-89.
4. Trusted Computing Group. (2019). "Trusted Platform Module Library Specification, Family 2.0."
5. Parno, B., McCune, J. M., & Perrig, A. (2010). "Bootstrapping Trust in Commodity Computers." *IEEE Symposium on Security and Privacy*.
6. Dodis, Y., Reyzin, L., & Smith, A. (2004). "On the (Im)possibility of Cryptography with Imperfect Randomness." *FOCS*.
7. RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP).
8. RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA).
9. Laurie, B., Langley, A., & Kasper, E. (2013). "Certificate Transparency." RFC 6962.

---

## Appendix A: Example Verification Output

```
$ ritma verify-proof /var/ritma_out/ns-demo
RITMA_OUT bundle verify (path=/var/ritma_out/ns-demo)
  status: OK
  hours_verified: 24
  micro_windows_verified: 1440
  chain_links_verified: 24
  signatures_verified: 2928
  bytes_verified: 15728640
```

```json
{
  "bundle_type": "ritma_out",
  "path": "/var/ritma_out/ns-demo",
  "valid": true,
  "errors": [],
  "warnings": [],
  "stats": {
    "hours_verified": 24,
    "micro_windows_verified": 1440,
    "chain_links_verified": 24,
    "signatures_verified": 2928,
    "bytes_verified": 15728640
  }
}
```
