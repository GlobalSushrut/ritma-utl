# Ritma Transparent Segment Ledger (RTSL) Specification

**Version:** 1.0  
**Status:** Draft  
**Date:** 2026-01-19  

---

## Abstract

RTSL (Ritma Transparent Segment Ledger) is a production-grade output format for forensic audit logs that combines:

- **WARC-style append-only segments** for stability and reduced filesystem operations
- **Certificate Transparency (CT) Merkle proofs** for cryptographic append-only guarantees
- **Sigstore/Rekor sharding** for infinite scalability
- **IPLD CAR content-addressing** for deduplication and efficient exports
- **Git packfile delta compression** for storage efficiency
- **Merkle Mountain Range (MMR)** for efficient append-only proofs

This format replaces the current "folder dump" approach with a court-ready, production-stable, easily traceable archive system.

---

## Table of Contents

1. [Design Goals](#1-design-goals)
2. [Directory Structure](#2-directory-structure)
3. [Segment Files (.rseg)](#3-segment-files-rseg)
4. [Index Files (.ridx)](#4-index-files-ridx)
5. [Root Files (.rroot)](#5-root-files-rroot)
6. [Merkle Structure](#6-merkle-structure)
7. [Sharding Strategy](#7-sharding-strategy)
8. [Content-Addressed Blocks](#8-content-addressed-blocks)
9. [Locator System](#9-locator-system)
10. [Verification Protocol](#10-verification-protocol)
11. [Compression](#11-compression)
12. [Cold Storage & Retention](#12-cold-storage-retention)
13. [Court Admissibility](#13-court-admissibility)
14. [Migration from v1](#14-migration-from-v1)
15. [References](#15-references)

---

## 1. Design Goals

### 1.1 Stability (Production-Critical)

| Problem (Current) | Solution (RTSL) | Source |
|-------------------|-----------------|--------|
| Millions of small files | Append-only segment files | WARC ISO 28500 [1] |
| Filesystem exhaustion | Few large files per hour | WARC best practices |
| Crash corruption | Atomic segment finalization | WAL pattern [2] |
| Index corruption | Rebuildable from segments | Git packfile design [3] |

### 1.2 Traceability (Court-Ready)

| Requirement | RTSL Feature | Source |
|-------------|--------------|--------|
| Precise event location | LOC = (shard, segment, offset, len) | WARC record offsets |
| Tamper detection | Merkle inclusion proofs | RFC 6962/9162 [4][5] |
| Append-only guarantee | Signed Tree Heads (STH) | Certificate Transparency |
| Chain of custody | Custody records in segments | NIST IR 8387 [6] |

### 1.3 Scalability (Enterprise-Grade)

| Challenge | Solution | Source |
|-----------|----------|--------|
| Unbounded growth | Time-based sharding | Sigstore/Rekor [7] |
| Verification cost | MMR for O(log n) proofs | Grin MMR [8] |
| Storage cost | Delta compression + dedup | Git packfiles [3] |
| Export size | Content-addressed blocks | IPLD CAR [9] |

---

## 2. Directory Structure

```
ledger/
├── v2/                           # Format version
│   ├── CURRENT                   # Active shard pointer
│   ├── shards/
│   │   └── 2026/
│   │       └── 01/
│   │           └── 19/
│   │               └── 10/       # Hour shard (YYYYMMDDHH)
│   │                   ├── segments/
│   │                   │   ├── 00.rseg      # Minute 00-09
│   │                   │   ├── 10.rseg      # Minute 10-19
│   │                   │   ├── 20.rseg      # ...
│   │                   │   ├── 30.rseg
│   │                   │   ├── 40.rseg
│   │                   │   └── 50.rseg
│   │                   ├── index/
│   │                   │   ├── time.ridx    # Time → offset index
│   │                   │   ├── object.ridx  # ObjectID → offsets
│   │                   │   └── hash.ridx    # ContentHash → offset
│   │                   ├── roots/
│   │                   │   ├── hour.rroot   # Signed hour root
│   │                   │   └── hour.rroot.sig
│   │                   └── blocks/
│   │                       └── *.rblk       # Content-addressed blocks
│   ├── chain/
│   │   ├── chain.rchn            # Append-only chain file
│   │   └── chain.rchn.sig
│   └── _meta/
│       ├── ledger.cbor           # Ledger metadata
│       ├── keys/
│       │   └── pubkeys.cbor      # Public keys for verification
│       └── schema/
│           └── v2.cbor           # Schema definitions
```

### 2.1 File Naming Convention

| Pattern | Description | Example |
|---------|-------------|---------|
| `{MM}.rseg` | Segment for minutes MM-MM+9 | `00.rseg`, `10.rseg` |
| `{type}.ridx` | Index by type | `time.ridx`, `object.ridx` |
| `hour.rroot` | Signed hour root | Single file per hour |
| `{hash}.rblk` | Content-addressed block | `a1b2c3...d4.rblk` |

---

## 3. Segment Files (.rseg)

### 3.1 Format Overview

Segment files are **append-only** containers holding multiple records, inspired by WARC ISO 28500 [1].

```
┌─────────────────────────────────────────────────────────────┐
│ Segment Header (fixed)                                      │
├─────────────────────────────────────────────────────────────┤
│ Record 0: [varint len][Record Header][Record Body]          │
├─────────────────────────────────────────────────────────────┤
│ Record 1: [varint len][Record Header][Record Body]          │
├─────────────────────────────────────────────────────────────┤
│ ...                                                         │
├─────────────────────────────────────────────────────────────┤
│ Record N: [varint len][Record Header][Record Body]          │
├─────────────────────────────────────────────────────────────┤
│ Segment Footer (on finalization)                            │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Segment Header

```
CBOR Array (tag: "ritma-seg@1.0"):
[
  "ritma-seg@1.0",           // [0] Format tag
  2,                         // [1] Version
  "2026-01-19T10:00:00Z",    // [2] Start timestamp (ISO 8601)
  "node-abc123",             // [3] Node ID
  "2026011910",              // [4] Shard ID (YYYYMMDDHH)
  0,                         // [5] Segment index (0-5 for 10-min segments)
  <prev_segment_hash>,       // [6] Previous segment hash (32 bytes) or null
  {}                         // [7] Extensions (reserved)
]
```

**Size:** ~150 bytes typical

### 3.3 Record Structure

Each record follows the WARC-inspired framing:

```
┌──────────────────────────────────────────────────────────┐
│ Length Prefix (LEB128 varint)                            │
├──────────────────────────────────────────────────────────┤
│ Record Header (CBOR)                                     │
├──────────────────────────────────────────────────────────┤
│ Record Body (CBOR, optionally compressed)                │
└──────────────────────────────────────────────────────────┘
```

#### 3.3.1 Record Header

```
CBOR Array (tag: "ritma-rec@1.0"):
[
  "ritma-rec@1.0",           // [0] Record tag
  <record_type>,             // [1] Type enum (see below)
  <record_id>,               // [2] UUID or sequential ID
  <timestamp_ns>,            // [3] Nanosecond timestamp (i64)
  <body_length>,             // [4] Body length in bytes
  <body_hash>,               // [5] SHA-256 of body (32 bytes)
  <compression>,             // [6] Compression: 0=none, 1=zstd
  {}                         // [7] Extensions
]
```

#### 3.3.2 Record Types

| Code | Type | Description |
|------|------|-------------|
| 0 | `segment_info` | Segment metadata (first record) |
| 1 | `event` | Canonical event atom |
| 2 | `custody` | Custody transfer record |
| 3 | `snapshot` | State snapshot chunk |
| 4 | `block_ref` | Reference to content-addressed block |
| 5 | `micro_root` | Micro-window Merkle root |
| 6 | `attestation` | TPM or external attestation |
| 7 | `metadata` | Arbitrary metadata |
| 8 | `segment_seal` | Segment finalization (last record) |

### 3.4 Segment Footer (Seal Record)

When a segment is finalized:

```
CBOR Array (tag: "ritma-seal@1.0"):
[
  "ritma-seal@1.0",          // [0] Seal tag
  <record_count>,            // [1] Total records in segment
  <byte_count>,              // [2] Total bytes (excluding footer)
  <end_timestamp>,           // [3] Last record timestamp
  <segment_hash>,            // [4] SHA-256 of segment (excluding footer)
  <mmr_peaks>,               // [5] MMR peaks array for records
  <signature>                // [6] Ed25519 signature of [0..5]
]
```

### 3.5 Append-Only Guarantee

Per RFC 6962 Section 3 [4]:
> "A log is a single, ever-growing, append-only Merkle Tree"

RTSL enforces this by:
1. Segments are write-once after sealing
2. Each segment references previous segment hash
3. Segment seals are signed
4. MMR structure allows efficient append proofs

---

## 4. Index Files (.ridx)

Indexes are **rebuildable** from segments (crash-safe design per Git [3]).

### 4.1 Time Index (time.ridx)

Maps timestamps to segment offsets for fast time-range queries.

```
CBOR Map:
{
  "tag": "ritma-idx-time@1.0",
  "shard": "2026011910",
  "entries": [
    // Sorted by timestamp
    [<timestamp_ns>, <segment_idx>, <byte_offset>, <record_len>],
    [<timestamp_ns>, <segment_idx>, <byte_offset>, <record_len>],
    ...
  ],
  "built_at": <timestamp>,
  "segment_hashes": [<hash0>, <hash1>, ...]  // For validation
}
```

### 4.2 Object Index (object.ridx)

Maps object/entity IDs to all their occurrences.

```
CBOR Map:
{
  "tag": "ritma-idx-object@1.0",
  "shard": "2026011910",
  "entries": {
    "<object_id>": [
      [<segment_idx>, <byte_offset>, <record_len>, <timestamp_ns>],
      ...
    ],
    ...
  }
}
```

### 4.3 Hash Index (hash.ridx)

Maps content hashes to offsets (for deduplication).

```
CBOR Map:
{
  "tag": "ritma-idx-hash@1.0",
  "shard": "2026011910",
  "entries": {
    "<sha256_hex>": [<segment_idx>, <byte_offset>],
    ...
  }
}
```

---

## 5. Root Files (.rroot)

### 5.1 Hour Root Structure

Per RFC 9162 Section 4.10 (Signed Tree Head) [5]:

```
CBOR Array (tag: "ritma-hour-root@2.0"):
[
  "ritma-hour-root@2.0",     // [0] Tag
  "2026011910",              // [1] Shard ID
  "node-abc123",             // [2] Node ID
  <timestamp>,               // [3] Signing timestamp
  <tree_size>,               // [4] Number of records in hour
  <mmr_root>,                // [5] MMR root hash (32 bytes)
  <segment_roots>,           // [6] Array of segment seal hashes
  <prev_hour_root>,          // [7] Previous hour root hash
  <extensions>               // [8] Reserved
]
```

### 5.2 Signature File (.rroot.sig)

```
CBOR Array (tag: "ritma-sig@1.0"):
[
  "ritma-sig@1.0",
  "hour_root",               // Signed artifact type
  "<key_id>",                // Signing key identifier
  <signature>                // Ed25519 signature (64 bytes)
]
```

---

## 6. Merkle Structure

### 6.1 Merkle Mountain Range (MMR)

RTSL uses MMR instead of balanced Merkle trees because:

1. **Append-only friendly**: No rebalancing needed (per Grin [8])
2. **Efficient proofs**: O(log n) inclusion proofs
3. **Incremental updates**: Only new peaks computed on append

```
Height 3:           14
                   /  \
Height 2:         6    13
                 / \   / \
Height 1:       2   5 9  12
               /\ /\ /\  /\
Height 0:     0 1 3 4 7 8 10 11
              └─────────────────── Leaves (records)
```

### 6.2 Hash Function

Per RFC 9162 Section 2.1 [5]:

```
Leaf hash:     H(0x00 || record_bytes)
Internal hash: H(0x01 || left_hash || right_hash)
```

Where H = SHA-256 (FIPS 180-4).

### 6.3 Proof Structure

Inclusion proof for record at position `m` in tree of size `n`:

```
CBOR Array (tag: "ritma-proof@1.0"):
[
  "ritma-proof@1.0",
  <leaf_index>,              // Position in MMR
  <tree_size>,               // MMR size at proof time
  <path>,                    // Array of sibling hashes
  <peak_hashes>              // MMR peaks for verification
]
```

---

## 7. Sharding Strategy

Per Sigstore/Rekor sharding best practices [7]:

### 7.1 Shard Boundaries

| Shard Level | ID Format | Duration | Use Case |
|-------------|-----------|----------|----------|
| Hour | YYYYMMDDHH | 1 hour | Default production |
| Day | YYYYMMDD | 24 hours | Low-volume systems |
| Minute | YYYYMMDDHHmm | 1 minute | High-volume systems |

### 7.2 Shard Lifecycle

```
ACTIVE → SEALING → SEALED → ARCHIVED
   │         │         │         │
   │         │         │         └── Cold storage
   │         │         └── Immutable, verified
   │         └── Finalizing, no new writes
   └── Accepting writes
```

### 7.3 Cross-Shard Chain

The `chain.rchn` file links shards:

```
CBOR Array (tag: "ritma-chain@2.0"):
[
  "ritma-chain@2.0",
  [
    // Each entry links to previous
    {
      "shard": "2026011909",
      "hour_root": <hash>,
      "prev_chain_hash": <hash>,
      "chain_hash": <hash>,
      "timestamp": <ts>,
      "signature": <sig>
    },
    {
      "shard": "2026011910",
      "hour_root": <hash>,
      "prev_chain_hash": <hash>,  // Points to 2026011909
      "chain_hash": <hash>,
      "timestamp": <ts>,
      "signature": <sig>
    },
    ...
  ]
]
```

---

## 8. Content-Addressed Blocks

Per IPLD CAR specification [9]:

### 8.1 Block Format

Large payloads are stored as content-addressed blocks:

```
┌─────────────────────────────────────────┐
│ Block Header (CBOR)                     │
├─────────────────────────────────────────┤
│ Block Data (raw bytes, may be zstd)     │
└─────────────────────────────────────────┘
```

Header:
```
CBOR Array (tag: "ritma-blk@1.0"):
[
  "ritma-blk@1.0",
  <content_hash>,            // SHA-256 of uncompressed data
  <uncompressed_size>,
  <compressed_size>,         // 0 if not compressed
  <codec>                    // 0=raw, 1=cbor, 2=json
]
```

### 8.2 Block References

Records reference blocks by hash:

```
CBOR Array (tag: "ritma-blkref@1.0"):
[
  "ritma-blkref@1.0",
  <content_hash>,            // Reference to block
  <block_type>,              // What the block contains
  <metadata>                 // Type-specific metadata
]
```

### 8.3 Deduplication

Per Git packfile design [3]:
- Identical content → same hash → stored once
- Similar content → delta compression (future)

---

## 9. Locator System

Every record has a unique **Locator (LOC)**:

### 9.1 LOC Format

```
LOC := shard:segment:offset:length

Example: 2026011910:00:4096:512
         │          │  │    └── Record length (bytes)
         │          │  └── Byte offset in segment
         │          └── Segment index (00-50)
         └── Shard ID (hour)
```

### 9.2 LOC URI

```
ritma://node-abc123/2026011910/00/4096/512
        │           │          │  │    └── Length
        │           │          │  └── Offset
        │           │          └── Segment
        │           └── Shard
        └── Node ID
```

### 9.3 LOC Resolution

```rust
fn resolve_loc(ledger: &Ledger, loc: &Loc) -> Result<Record> {
    let shard = ledger.get_shard(&loc.shard)?;
    let segment = shard.get_segment(loc.segment)?;
    let record = segment.read_at(loc.offset, loc.length)?;
    Ok(record)
}
```

---

## 10. Verification Protocol

### 10.1 Offline Verification Steps

1. **Segment Integrity**
   - Verify each segment's seal signature
   - Recompute segment hash, compare to seal
   - Verify prev_segment_hash chain

2. **MMR Verification**
   - Rebuild MMR from segment records
   - Compare peaks to sealed peaks
   - Verify hour root matches MMR root

3. **Chain Verification**
   - Verify hour root signatures
   - Verify prev_hour_root linkage
   - Verify chain.rchn consistency

4. **Record Verification**
   - For specific record: compute inclusion proof
   - Verify proof against hour root

### 10.2 Inclusion Proof Verification

Per RFC 9162 Section 2.1.3 [5]:

```rust
fn verify_inclusion(
    record: &[u8],
    proof: &InclusionProof,
    root: &[u8; 32]
) -> bool {
    let leaf_hash = sha256(&[0x00, record].concat());
    let mut current = leaf_hash;
    
    for (i, sibling) in proof.path.iter().enumerate() {
        let bit = (proof.leaf_index >> i) & 1;
        current = if bit == 0 {
            sha256(&[0x01, &current, sibling].concat())
        } else {
            sha256(&[0x01, sibling, &current].concat())
        };
    }
    
    // Combine with MMR peaks
    current == *root
}
```

---

## 11. Compression

### 11.1 Strategy

Per WARC Annex D [1]:

| Level | Compression | Use Case |
|-------|-------------|----------|
| Record | Optional zstd per record | Mixed content |
| Segment | Whole-segment gzip | Archival |
| Block | zstd for large blocks | Snapshots |

### 11.2 Record-Level Compression

```
Record Header: compression = 1 (zstd)
Record Body: zstd-compressed CBOR
```

### 11.3 Segment-Level Compression

For archival, entire `.rseg` can be gzip-wrapped:
- Filename: `00.rseg.gz`
- Random access via gzip member boundaries (per WARC)

---

## 12. Cold Storage & Retention

### 12.1 Tiered Storage

| Tier | Content | Retention | Access |
|------|---------|-----------|--------|
| Hot | Last 7 days segments | Always | Immediate |
| Warm | Last 90 days roots + indexes | Always | Fast |
| Cold | Older segments | Per policy | Minutes |
| Archive | Sealed shards | Years | Hours |

### 12.2 Minimal Verification Set

Even with cold segments, verification possible with:
- `chain.rchn` (tiny, always hot)
- `hour.rroot` files (tiny, always hot)
- Specific segment (fetch on demand)

---

## 13. Court Admissibility

Per NIST IR 8387 [6] and digital forensics standards:

### 13.1 Chain of Custody

RTSL provides:
- **Immutable records**: Append-only, signed segments
- **Precise timestamps**: Nanosecond resolution
- **Cryptographic binding**: Every record in Merkle tree
- **Verifiable history**: Inclusion proofs

### 13.2 Evidence Export

```
ritma export --loc 2026011910:00:4096:512 --format court-package

Output:
├── record.cbor              # The actual record
├── inclusion_proof.cbor     # Merkle proof
├── hour_root.cbor           # Signed root
├── chain_excerpt.cbor       # Relevant chain entries
├── verification_report.pdf  # Human-readable report
└── manifest.json            # Package manifest
```

### 13.3 Verification Report

```
RITMA EVIDENCE VERIFICATION REPORT
==================================
Record LOC: 2026011910:00:4096:512
Record Hash: a1b2c3...
Timestamp: 2026-01-19T10:00:37.123456789Z

VERIFICATION RESULTS:
[✓] Record hash matches content
[✓] Inclusion proof valid against hour root
[✓] Hour root signature valid (key: node-abc123-ed25519)
[✓] Chain linkage verified (prev: 2026011909)
[✓] TPM attestation binding verified

CHAIN OF CUSTODY:
- Created: 2026-01-19T10:00:37Z by node-abc123
- Sealed: 2026-01-19T10:10:00Z
- Verified: 2026-01-19T17:56:00Z by verifier-xyz
```

---

## 14. Migration from v1

### 14.1 Compatibility

| v1 Artifact | v2 Equivalent |
|-------------|---------------|
| `windows/YYYY/MM/DD/HH/micro/*.cbor` | `shards/YYYY/MM/DD/HH/segments/*.rseg` |
| `windows/.../proofs/hour_root.cbor` | `shards/.../roots/hour.rroot` |
| `windows/.../proofs/chain.cbor` | `chain/chain.rchn` |
| `_meta/keys/pubkeys.cbor` | `_meta/keys/pubkeys.cbor` (unchanged) |

### 14.2 Migration Tool

```bash
ritma migrate-ledger --from v1 --to v2 --input ./RITMA_OUT --output ./ledger
```

---

## 15. References

1. **[WARC ISO 28500]** The WARC Format 1.1, IIPC. https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/

2. **[WAL]** Write-Ahead Logging. SQLite. https://sqlite.org/wal.html

3. **[Git Packfiles]** Git Internals - Packfiles. https://git-scm.com/book/en/v2/Git-Internals-Packfiles

4. **[RFC 6962]** Certificate Transparency. https://www.rfc-editor.org/rfc/rfc6962.html

5. **[RFC 9162]** Certificate Transparency Version 2.0. https://www.rfc-editor.org/rfc/rfc9162.html

6. **[NIST IR 8387]** Digital Evidence Preservation. https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8387.pdf

7. **[Sigstore Sharding]** Rekor Log Sharding. https://docs.sigstore.dev/logging/sharding/

8. **[Grin MMR]** Merkle Mountain Ranges. https://docs.grin.mw/wiki/chain-state/merkle-mountain-range/

9. **[IPLD CAR]** Content Addressable aRchives v1. https://ipld.io/specs/transport/car/carv1/

---

## 16. Production Readiness Checklist

This section defines **10 hard requirements** for production stability. Each requirement includes MUST/SHOULD levels, failure modes, and RTSL implementation details.

### 16.1 Crash-Safe Writes (Atomic + Recoverable)

**Requirement:** Power loss mid-write MUST NOT corrupt the ledger.

| Level | Requirement | RTSL Implementation |
|-------|-------------|---------------------|
| MUST | No partial records visible after crash | Write-ahead: full record written before advancing offset pointer |
| MUST | Recovery without data loss | Replay from last sealed segment + truncate incomplete records |
| SHOULD | Sub-second recovery time | Index rebuild from segment headers only (not full scan) |

**Implementation (No External DB):**
```
Write sequence:
1. Append [varint_len][header][body] to segment file
2. fsync() segment file
3. Update in-memory offset pointer
4. Periodically fsync() index file

Recovery sequence:
1. Read segment header → get expected record count
2. Scan forward, validating each [varint_len][header][body]
3. Truncate at first invalid/incomplete record
4. Rebuild index from valid records
```

**Failure Modes:**
- Partial varint write → detected by invalid length, truncated
- Partial record write → detected by length mismatch, truncated
- Index corruption → rebuilt from segments (indexes are derived, not source of truth)

**References:** SQLite WAL [2], ARIES recovery algorithm

---

### 16.2 Append-Only Immutability

**Requirement:** Once written, records MUST NEVER be edited in place.

| Level | Requirement | RTSL Implementation |
|-------|-------------|---------------------|
| MUST | No in-place modification | Segment files opened O_APPEND only |
| MUST | Corrections as new records | `correction` record type with `corrects_loc` field |
| MUST | History always preserved | Sealed segments are read-only (chmod 0444) |
| SHOULD | Detect tampering | MMR root changes if any record modified |

**Correction Record Format:**
```cbor
["ritma-rec@1.0", 9, <uuid>, <ts>, <len>, <hash>, 0, {
  "corrects_loc": "2026011910:00:4096:512",
  "reason": "data_entry_error",
  "correction_type": "supersede"  // or "void", "amend"
}]
```

**References:** Event Sourcing patterns, RFC 6962 append-only logs

---

### 16.3 Deterministic Canonical Hashing

**Requirement:** Same input MUST produce identical hash across all implementations.

| Level | Requirement | RTSL Implementation |
|-------|-------------|---------------------|
| MUST | Cross-language consistency | RFC 8949 Core Deterministic Encoding |
| MUST | Reproducible hashes | Canonical CBOR rules strictly enforced |
| MUST | No floating-point ambiguity | Integers only for timestamps; floats banned in hashed fields |

**Canonical CBOR Rules (per RFC 8949 §4.2.1):**
1. Preferred serialization (shortest form)
2. Map keys sorted by encoded byte order
3. No indefinite-length items
4. Integers: smallest encoding that fits
5. No duplicate map keys

**Hash Function:** SHA-256 (FIPS 180-4), same as Certificate Transparency

**Test Vectors:**
```
Input: {"b": 2, "a": 1}
Canonical CBOR: a2 61 61 01 61 62 02  (keys sorted: "a" before "b")
SHA-256: 9f86d08...
```

**References:** RFC 8949 §4.2, FIDO CTAP2 canonical CBOR

---

### 16.4 Chain-of-Custody Correctness

**Requirement:** Every event MUST link to previous, enabling instant gap/reorder detection.

| Level | Requirement | RTSL Implementation |
|-------|-------------|---------------------|
| MUST | Sequential numbering | `seq` field in every record (per-segment, monotonic) |
| MUST | Hash chaining | `prev_record_hash` in record header |
| MUST | Gap detection | Verifier checks seq[i] == seq[i-1] + 1 |
| MUST | Double-write detection | Same seq + different hash = error |

**Record Linkage:**
```
Record N:   seq=42, prev_hash=H(Record N-1), ...
Record N+1: seq=43, prev_hash=H(Record N), ...
```

**Segment Linkage:**
```
Segment M:   prev_segment_hash = H(Segment M-1 seal)
Segment M+1: prev_segment_hash = H(Segment M seal)
```

**Verification Checks:**
- `seq` strictly increasing within segment
- `prev_record_hash` matches computed hash of previous record
- `prev_segment_hash` matches sealed hash of previous segment
- No gaps in segment sequence (00, 10, 20, 30, 40, 50)

---

### 16.5 Scales Without Filesystem Pain

**Requirement:** MUST handle months/years of data without "millions of tiny files" problem.

| Level | Requirement | RTSL Implementation |
|-------|-------------|---------------------|
| MUST | < 100 files per hour | 6 segments + 3 indexes + 2 roots = 11 files/hour |
| MUST | No inode exhaustion | Segments contain thousands of records each |
| SHOULD | < 1000 files per day | ~264 files/day (11 × 24) |
| SHOULD | Predictable growth | Linear with time, not with event count |

**File Count Analysis:**
```
Per hour:  6 segments + 3 indexes + 2 roots + ~10 blocks = ~21 files
Per day:   ~504 files
Per month: ~15,120 files
Per year:  ~183,960 files (manageable on any filesystem)
```

**Contrast with v1:**
```
v1: 1 file per micro-window (10s) = 360 files/hour = 8,640 files/day
v2: 21 files/hour = 504 files/day (17x reduction)
```

---

### 16.6 Fast Tracing (O(1)-ish Lookup)

**Requirement:** Given time or object_id, MUST jump to exact records without full scan.

| Level | Requirement | RTSL Implementation |
|-------|-------------|---------------------|
| MUST | Time → records in O(log n) | `time.ridx`: sorted array, binary search |
| MUST | Object → records in O(1) | `object.ridx`: hash map object_id → offsets |
| SHOULD | < 10ms for any lookup | Index fits in memory for hot shards |

**Index Structures (Simple Files, No DB):**

**time.ridx** (sorted array):
```cbor
{
  "entries": [
    [1705665600000000000, 0, 0, 512],      // ts_ns, seg, offset, len
    [1705665600100000000, 0, 512, 256],
    ...
  ]
}
```
Lookup: binary search on timestamp → segment + offset

**object.ridx** (hash map):
```cbor
{
  "entries": {
    "obj-abc123": [[0, 1024, 512, ts1], [0, 2048, 256, ts2]],
    "obj-def456": [[1, 0, 1024, ts3]],
    ...
  }
}
```
Lookup: direct key access → list of (segment, offset, len, ts)

---

### 16.7 Multi-Level Provability

**Requirement:** MUST support proofs at record, segment, hour, and chain levels.

| Level | Proof Type | What It Proves | Size |
|-------|------------|----------------|------|
| Record | MMR inclusion | "Record X exists in segment S" | O(log n) hashes |
| Segment | Seal signature | "Segment S was finalized by node N at time T" | 64 bytes |
| Hour | Root signature | "Hour H contains segments S1..S6 with root R" | 64 bytes |
| Chain | Chain linkage | "Hours H1→H2→...→Hn form append-only sequence" | O(n) × 32 bytes |

**Proof Generation:**
```rust
// Record inclusion proof
fn prove_record(loc: &Loc) -> InclusionProof {
    let segment = load_segment(loc.shard, loc.segment);
    let mmr = segment.rebuild_mmr();
    mmr.prove(loc.record_index)
}

// Verify: recompute root from proof, compare to signed hour root
```

**Future Extension:** ZK proofs for "state transitioned correctly" (not in v1.0)

---

### 16.8 Selective Disclosure Exports (ProofPack Tiers)

**Requirement:** MUST support tiered exports from minimal to full.

| Tier | Contents | Size | Use Case |
|------|----------|------|----------|
| **Micro** | Roots + chain + specific record proofs | ~10 KB | Court exhibit, audit summary |
| **Mini** | Above + relevant segment(s) | ~1 MB | Incident investigation |
| **Full** | All segments + blocks for time range | ~100 MB+ | Complete forensic package |

**Export Commands:**
```bash
# Micro: just prove one record existed
ritma export --loc 2026011910:00:4096:512 --tier micro

# Mini: include the segment containing the record
ritma export --loc 2026011910:00:4096:512 --tier mini

# Full: entire hour
ritma export --shard 2026011910 --tier full
```

**Micro Export Contents:**
```
export/
├── record.cbor           # The specific record
├── proof.cbor            # MMR inclusion proof
├── segment_seal.cbor     # Segment seal (signed)
├── hour_root.cbor        # Hour root (signed)
├── chain_excerpt.cbor    # Relevant chain entries
└── manifest.json
```

---

### 16.9 Retention + Cold Storage Without Breaking Verification

**Requirement:** MUST verify integrity even after moving segments to cold storage.

| Level | Requirement | RTSL Implementation |
|-------|-------------|---------------------|
| MUST | Verify without segments | Keep roots + chain (tiny) forever |
| MUST | Prove record existed | Inclusion proof works with just root |
| SHOULD | On-demand segment fetch | LOC → fetch from cold storage if needed |

**What to Keep Forever (Tiny):**
```
Per hour: hour.rroot (< 1 KB) + hour.rroot.sig (< 1 KB)
Per year: ~17 MB of roots (trivial)
```

**What Can Be Archived/Deleted:**
```
segments/*.rseg     → Archive to S3/Glacier after 90 days
blocks/*.rblk       → Archive after 90 days
index/*.ridx        → Rebuild from segments if needed
```

**Verification with Cold Segments:**
```
1. User requests proof for LOC 2024011910:00:4096:512
2. System checks: segment in hot storage? No.
3. System fetches segment from cold storage (async)
4. System generates proof, returns to user
5. Proof verifies against always-hot hour root
```

---

### 16.10 Operational Observability + Self-Checks

**Requirement:** MUST provide built-in health checks and diagnostics.

**CLI Commands:**

```bash
# Full verification
ritma ledger doctor --path ./ledger
```

**Doctor Output:**
```
RITMA LEDGER HEALTH CHECK
=========================
Path: ./ledger
Format: RTSL v2

STRUCTURE CHECKS:
[✓] CURRENT file exists and valid
[✓] Chain file intact (1,234 entries)
[✓] All shards have hour roots

INTEGRITY CHECKS:
[✓] Chain hash continuity verified
[✓] All hour roots properly signed
[✓] Segment seals verified (7,404 segments)
[✓] MMR roots match sealed values

INDEX CHECKS:
[✓] time.ridx consistent with segments
[✓] object.ridx consistent with segments
[!] hash.ridx missing for shard 2026011823 (rebuildable)

STORAGE METRICS:
  Total shards:     1,234
  Total segments:   7,404
  Total records:    12,456,789
  Total size:       45.2 GB
  Hot storage:      12.1 GB (last 7 days)
  Cold storage:     33.1 GB

RECOMMENDATIONS:
- Rebuild hash.ridx for shard 2026011823
- Consider archiving shards older than 2025121910
```

**Metrics Exposed:**
```
ritma_ledger_records_total{shard="2026011910"} 12345
ritma_ledger_segments_total 7404
ritma_ledger_bytes_total 48573849234
ritma_ledger_last_seal_timestamp 1705665600
ritma_ledger_verification_errors_total 0
```

---

## 17. Design Principles: Lightweight & No External Dependencies

RTSL is designed to be **self-contained** with **no external database dependencies**:

| Principle | Implementation |
|-----------|----------------|
| No embedded DB | Plain files only (no RocksDB, SQLite, LMDB) |
| No complex indexes | Simple CBOR files, rebuildable from segments |
| Minimal dependencies | Only: SHA-256, Ed25519, CBOR, zstd |
| Portable | Works on any POSIX filesystem |
| Inspectable | `cbor2json` can read any file |

**Why No Embedded Database:**
- RocksDB/LMDB add 10+ MB binary size
- Complex failure modes (compaction, WAL, etc.)
- Harder to inspect/debug
- Overkill for append-only workload

**RTSL Approach:**
- Segments are the source of truth (append-only files)
- Indexes are derived (rebuildable)
- Roots are tiny (keep forever)
- Everything is CBOR (human-inspectable with tools)

---

## Appendix A: ABNF Grammar

```abnf
; Segment file
rseg-file = segment-header *record segment-seal

; Record
record = length-prefix record-header record-body
length-prefix = varint
record-header = cbor-array
record-body = cbor-value / compressed-cbor

; Varint (LEB128)
varint = 1*8OCTET

; CBOR types
cbor-array = <per RFC 8949>
cbor-value = <per RFC 8949>
```

## Appendix B: Example Segment Hex Dump

```
00000000: d9 d9 f7 88 6d 72 69 74  6d 61 2d 73 65 67 40 31  |....mritma-seg@1|
00000010: 2e 30 02 78 18 32 30 32  36 2d 30 31 2d 31 39 54  |.0.x.2026-01-19T|
00000020: 31 30 3a 30 30 3a 30 30  5a 6b 6e 6f 64 65 2d 61  |10:00:00Zknode-a|
00000030: 62 63 31 32 33 6a 32 30  32 36 30 31 31 39 31 30  |bc123j2026011910|
...
```

## Appendix C: CLI Examples

```bash
# Write events to ledger
ritma ledger write --event '{"type":"file_access",...}'

# Query by time range
ritma ledger query --from 2026-01-19T10:00:00Z --to 2026-01-19T11:00:00Z

# Get inclusion proof
ritma ledger prove --loc 2026011910:00:4096:512

# Verify entire ledger
ritma ledger verify --path ./ledger

# Export for court
ritma ledger export --loc 2026011910:00:4096:512 --format court-package
```

---

*End of RTSL Specification v1.0*
