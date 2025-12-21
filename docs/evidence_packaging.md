# Enterprise Evidence Packaging

This document describes Ritma's **enterprise-grade evidence packaging system** for auditors, regulators, and compliance teams.

---

## Overview

The evidence packaging system produces **signed, verifiable, tamper-evident bundles** of compliance artifacts that can be:

- **Exported** for external auditors
- **Verified** offline without Ritma infrastructure
- **Anchored** to external systems (blockchain, notary services)
- **Traced** back to specific SVC commits, CCTV frames, and infrastructure states

---

## Key Features

### 1. **Cryptographic Integrity**
- SHA-256 hashing of all artifacts
- Package-level hash over canonical manifest
- Optional HMAC-SHA256 or Ed25519 signatures
- Merkle proofs for individual records

### 2. **Chain Anchoring**
- Captures chain heads at package creation time:
  - `dig_index_head` — DigFile index chain
  - `policy_ledger_head` — Policy ledger chain
  - `svc_ledger_head` — SVC commit chain
  - `burn_chain_head` — Compliance burn chain
  - `search_events_head` — Search audit log chain

### 3. **Multi-Scope Support**
- **Policy Commit**: All evidence for a specific SVC commit
- **Compliance Burn**: All artifacts in a burn (e.g., Q4 2024 SOC2)
- **Time Range**: Evidence within a time window
- **Incident**: Forensic package for an incident
- **Custom**: Arbitrary filters (SVC, CCTV frame, actor DID)

### 4. **Artifact Types**
- DigFiles (immutable evidence bundles)
- Compliance Burns (Merkle-tree snapshots)
- Decision Events (policy decisions)
- Control Eval Records (compliance evaluations)
- Search Events (audit logs)
- Log Camera Frames (CCTV snapshots)
- Policy Snapshots
- Infrastructure Snapshots

### 5. **Metadata Enrichment**
Each artifact includes:
- **SVC commits** referenced
- **Infrastructure version** at capture time
- **CCTV frames** correlated
- **Actor DIDs** involved
- **Compliance framework** (SOC2, HIPAA, etc.)
- **Time range** covered

---

## Package Manifest Structure

```json
{
  "package_id": "pkg_acme_corp_1702400000",
  "format_version": 1,
  "created_at": 1702400000,
  "created_by": "did:ritma:auditor:alice",
  "tenant_id": "acme_corp",
  
  "scope": {
    "type": "compliance_burn",
    "burn_id": "burn_q4_2024_soc2",
    "framework": "SOC2"
  },
  
  "chain_heads": {
    "dig_index_head": "abc123...",
    "policy_ledger_head": "def456...",
    "svc_ledger_head": "ghi789...",
    "burn_chain_head": "jkl012...",
    "search_events_head": "mno345..."
  },
  
  "artifacts": [
    {
      "artifact_type": "dig_file",
      "artifact_id": "file_001",
      "path": "/digs/root_123/file_001.json",
      "hash": "sha256:...",
      "size_bytes": 102400,
      "metadata": {
        "merkle_root": "...",
        "record_count": 250,
        "svc_commits": ["svc_v2.1", "svc_v2.2"],
        "infra_version_id": "infra_prod_v5",
        "camera_frames": ["frame_001", "frame_002"],
        "actor_dids": ["did:ritma:user:bob"],
        "time_start": 1702300000,
        "time_end": 1702310000
      }
    },
    {
      "artifact_type": "compliance_burn",
      "artifact_id": "burn_q4_2024_soc2",
      "path": "/burns/burn_q4_2024_soc2.json",
      "hash": "sha256:...",
      "size_bytes": 51200,
      "metadata": {
        "burn_hash": "...",
        "prev_burn_hash": "...",
        "framework": "SOC2",
        "pass_rate": 0.98,
        "time_start": 1702200000,
        "time_end": 1702400000
      }
    }
  ],
  
  "security": {
    "hash_algorithm": "sha256",
    "package_hash": "fedcba...",
    "signature": {
      "signature_type": "ed25519",
      "signature_hex": "...",
      "signer_id": "utl_cli",
      "signed_at": 1702400000,
      "public_key_hex": "..."
    }
  },
  
  "metadata": {
    "purpose": "Q4 2024 SOC2 Audit",
    "auditor": "External Audit Firm XYZ"
  }
}
```

---

## CLI Usage

### Export a Package

```bash
# Export by policy commit
utl_cli EvidencePackageExport \
  --tenant acme_corp \
  --scope-type policy_commit \
  --scope-id svc_v2_commit_abc123 \
  --framework SOC2 \
  --out package_soc2_q4.json \
  --requester-did did:ritma:auditor:alice

# Export by compliance burn
utl_cli EvidencePackageExport \
  --tenant acme_corp \
  --scope-type burn \
  --scope-id burn_q4_2024_soc2 \
  --framework SOC2 \
  --out burn_package.json

# Export by time range
utl_cli EvidencePackageExport \
  --tenant acme_corp \
  --scope-type time_range \
  --scope-id 1702200000:1702400000 \
  --framework HIPAA \
  --out hipaa_q4.json
```

### Verify a Package

```bash
# Full verification (manifest + artifacts)
utl_cli EvidencePackageVerify \
  --manifest package_soc2_q4.json

# Skip artifact hash verification (faster)
utl_cli EvidencePackageVerify \
  --manifest package_soc2_q4.json \
  --skip-artifacts
```

### Signing Configuration

```bash
# Set signing key (HMAC-SHA256)
export UTLD_PACKAGE_SIG_KEY="hmac:$(openssl rand -hex 32)"

# Set signing key (Ed25519)
export UTLD_PACKAGE_SIG_KEY="ed25519:$(openssl rand -hex 32)"

# Set verification key (for HMAC, same as signing key)
export UTLD_PACKAGE_VERIFY_KEY="$(echo $UTLD_PACKAGE_SIG_KEY | cut -d: -f2)"
```

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `UTLD_DIG_INDEX_DB` | SQLite dig_index database | `./dig_index.sqlite` |
| `UTLD_DIG_STORAGE` | DigFile storage root | `./digs` |
| `UTLD_BURN_STORAGE` | Compliance burn storage | `./burns` |
| `UTLD_PACKAGE_SIG_KEY` | Signing key (`type:hex`) | None (unsigned) |
| `UTLD_PACKAGE_VERIFY_KEY` | Verification key (hex) | None |
| `UTLD_DIG_INDEX` | JSONL dig index file | `./dig_index.jsonl` |
| `UTLD_POLICY_LEDGER` | Policy ledger file | `./policy_ledger.jsonl` |
| `UTLD_SVC_LEDGER` | SVC ledger file | `./svc_ledger.jsonl` |
| `UTLD_BURN_CHAIN` | Burn chain index | `./burn_chain.jsonl` |
| `UTLD_SEARCH_EVENTS` | Search events log | `./search_events.jsonl` |

---

## Programmatic Usage

### Rust API

```rust
use evidence_package::{
    PackageBuilder, PackageSigner, PackageVerifier,
    PackageScope, SigningKey,
};

// Build a package
let scope = PackageScope::PolicyCommit {
    commit_id: "svc_v2_abc123".to_string(),
    framework: Some("SOC2".to_string()),
};

let mut manifest = PackageBuilder::new("acme_corp".to_string(), scope)
    .dig_index_db("./dig_index.sqlite".to_string())
    .dig_storage_root("./digs".to_string())
    .burn_storage_root("./burns".to_string())
    .created_by("did:ritma:auditor:alice".to_string())
    .metadata("purpose".to_string(), "Q4 Audit".to_string())
    .build()?;

// Sign the package
let key = SigningKey::generate_ed25519();
let signer = PackageSigner::new(key, "my_signer".to_string());
signer.sign(&mut manifest)?;

// Serialize
let json = serde_json::to_string_pretty(&manifest)?;
std::fs::write("package.json", json)?;

// Verify later
let content = std::fs::read_to_string("package.json")?;
let manifest: EvidencePackageManifest = serde_json::from_str(&content)?;

let verifier = PackageVerifier::new();
let result = verifier.verify(&manifest);

if result.is_valid() {
    println!("✓ Package verified");
} else {
    eprintln!("✗ Verification failed: {:?}", result.errors);
}
```

---

## Security Properties

### Tamper Evidence
- **Package hash** computed over canonical manifest (signature excluded)
- Any modification to manifest or artifact metadata invalidates the hash
- Signature verification ensures package hasn't been tampered with

### Non-Repudiation
- Ed25519 signatures provide cryptographic proof of origin
- Public key embedded in manifest for offline verification
- Signer ID tracks who created the package

### Chain Integrity
- Chain heads link package to specific points in append-only logs
- Verifiers can replay chains to confirm package state
- Prevents backdating or selective omission of evidence

### Artifact Verification
- Each artifact has SHA-256 hash
- Verifier can recompute hashes to detect file tampering
- Merkle proofs allow verification of individual records within DigFiles

---

## Use Cases

### 1. **Quarterly Compliance Audit**
```bash
# Export all SOC2 evidence for Q4 2024
utl_cli EvidencePackageExport \
  --tenant acme_corp \
  --scope-type burn \
  --scope-id burn_q4_2024_soc2 \
  --framework SOC2 \
  --out soc2_q4_2024.json \
  --requester-did did:ritma:auditor:external_firm

# Auditor verifies offline
utl_cli EvidencePackageVerify --manifest soc2_q4_2024.json
```

### 2. **Incident Forensics**
```bash
# Export all evidence for incident time window
utl_cli EvidencePackageExport \
  --tenant acme_corp \
  --scope-type time_range \
  --scope-id 1702350000:1702360000 \
  --out incident_2024_12_12.json \
  --requester-did did:ritma:soc:analyst
```

### 3. **Regulator Request**
```bash
# Export evidence for specific policy version
utl_cli EvidencePackageExport \
  --tenant acme_corp \
  --scope-type policy_commit \
  --scope-id policy_v3_commit_xyz \
  --framework HIPAA \
  --out regulator_request_hipaa.json \
  --requester-did did:ritma:regulator:hhs
```

### 4. **Continuous Compliance**
```bash
# Automated daily export for compliance monitoring
#!/bin/bash
TODAY=$(date +%s)
YESTERDAY=$((TODAY - 86400))

utl_cli EvidencePackageExport \
  --tenant acme_corp \
  --scope-type time_range \
  --scope-id ${YESTERDAY}:${TODAY} \
  --out daily_$(date +%Y%m%d).json
```

---

## Integration Points

### External Anchoring
- Package hash can be anchored to blockchain or notary services
- Chain heads provide tamper-evident checkpoints
- Enables time-stamping and external verification

### SIEM / Log Management
- Packages can be ingested into Splunk, ELK, etc.
- Artifacts are JSON, easily parsed and indexed
- Search events provide audit trail of package creation

### Compliance Platforms
- Export to GRC tools (ServiceNow, Archer, etc.)
- Automated evidence collection for frameworks
- API-friendly JSON format

---

## Future Enhancements

- **Archive Format**: Tar/zip bundles with manifest + artifacts
- **Incremental Packages**: Delta packages referencing previous exports
- **Multi-Tenant Packages**: Cross-tenant evidence for shared services
- **SBOM Integration**: Software Bill of Materials for policy/infra versions
- **Notarization**: Automatic timestamping via RFC 3161 TSA
- **Encryption**: AES-256-GCM encrypted packages for sensitive data

---

## Summary

Ritma's evidence packaging system provides **enterprise-grade, cryptographically verifiable compliance artifacts** that meet the highest standards for:

- **Auditability**: Complete chain of custody from capture to export
- **Integrity**: Tamper-evident hashing and signing
- **Traceability**: SVC, CCTV, and actor correlation
- **Portability**: Offline verification without Ritma infrastructure
- **Compliance**: SOC2, HIPAA, GDPR, and custom framework support

**The packaging layer is production-ready and hardened for enterprise use.**
