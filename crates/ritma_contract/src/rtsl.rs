use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::merkle_advanced::{MerkleMountainRange, TiledMerkleTree, VectorClock};
use crate::StorageContract;
use chrono::{Datelike, Timelike, Utc};
use ciborium;
use hex;
use sha2::{Digest, Sha256};

#[cfg(test)]
use std::sync::{Mutex, OnceLock};

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn maybe_sign_file(path: &Path, sig_path: &Path, artifact: &str) -> std::io::Result<()> {
    let Ok(key_id) = std::env::var("RITMA_KEY_ID") else {
        return Ok(());
    };
    let key_id = key_id.trim().to_string();
    if key_id.is_empty() {
        return Ok(());
    }

    // Opt-in switch to avoid accidental signing in dev/test environments.
    if !env_truthy("RITMA_OUT_RTSL_SIGN") {
        return Ok(());
    }

    let ks = match node_keystore::NodeKeystore::from_env() {
        Ok(ks) => ks,
        Err(e) => {
            return Err(std::io::Error::other(format!(
                "failed to load node keystore for signing ({artifact}): {e}"
            )))
        }
    };

    let bytes = std::fs::read(path)?;
    let digest_hex = sha256_hex(&bytes);
    let sig_hex = ks
        .sign_bytes(&key_id, &bytes)
        .map_err(|e| std::io::Error::other(format!("sign failed ({artifact}): {e}")))?;

    let tuple = (
        "ritma-sig@0.1",
        artifact,
        key_id.as_str(),
        digest_hex.as_str(),
        sig_hex.as_str(),
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&tuple, &mut buf).map_err(std::io::Error::other)?;
    write_atomic(sig_path, &buf)
}

fn append_framed_cbor(path: &Path, value: &impl serde::Serialize) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let bytes = {
        let mut buf: Vec<u8> = Vec::new();
        ciborium::into_writer(value, &mut buf).map_err(std::io::Error::other)?;
        buf
    };
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let len = bytes.len() as u32;
    f.write_all(&len.to_le_bytes())?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    Ok(())
}

fn read_framed_cbor(path: &Path) -> std::io::Result<Vec<ciborium::value::Value>> {
    let bytes = std::fs::read(path)?;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[i..i + 4]);
        let len = u32::from_le_bytes(len_bytes) as usize;
        i += 4;
        if i + len > bytes.len() {
            break;
        }
        let v = ciborium::from_reader::<ciborium::value::Value, _>(&bytes[i..i + len])
            .map_err(std::io::Error::other)?;
        out.push(v);
        i += len;
    }
    Ok(out)
}

fn decode_32_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn compute_hour_root_from_time_index(time_idx: &Path) -> std::io::Result<([u8; 32], u64)> {
    let mut items: Vec<(i64, [u8; 32])> = Vec::new();
    for v in read_framed_cbor(time_idx)? {
        let ciborium::value::Value::Array(arr) = v else {
            continue;
        };
        if arr.len() < 8 {
            continue;
        }
        let Some(ciborium::value::Value::Text(tag)) = arr.get(0) else {
            continue;
        };
        if tag != "ritma-idx-time@0.1" {
            continue;
        }
        let ts_ns = match arr.get(2) {
            Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
            _ => 0,
        };
        let Some(ciborium::value::Value::Text(root_hex)) = arr.get(7) else {
            continue;
        };
        let Some(root) = decode_32_hex(root_hex) else {
            continue;
        };
        items.push((ts_ns, root));
    }

    items.sort_by(|a, b| a.0.cmp(&b.0));
    let leaves: Vec<[u8; 32]> = items.into_iter().map(|(_, r)| r).collect();
    let root = crate::merkle_root_sha256(&leaves);
    Ok((root, leaves.len() as u64))
}

fn read_prev_hour_root(chain_path: &Path) -> std::io::Result<Option<[u8; 32]>> {
    if !chain_path.exists() {
        return Ok(None);
    }
    let vals = read_framed_cbor(chain_path)?;
    for v in vals.into_iter().rev() {
        let ciborium::value::Value::Array(arr) = v else {
            continue;
        };
        if arr.len() < 7 {
            continue;
        }
        let Some(ciborium::value::Value::Text(tag)) = arr.get(0) else {
            continue;
        };
        if tag != "ritma-chain@0.1" {
            continue;
        }
        let Some(ciborium::value::Value::Text(hour_root_hex)) = arr.get(5) else {
            continue;
        };
        return Ok(decode_32_hex(hour_root_hex));
    }
    Ok(None)
}

fn read_last_chain_entry(chain_path: &Path) -> std::io::Result<Option<(i64, [u8; 32])>> {
    if !chain_path.exists() {
        return Ok(None);
    }
    let vals = read_framed_cbor(chain_path)?;
    for v in vals.into_iter().rev() {
        let ciborium::value::Value::Array(arr) = v else {
            continue;
        };
        if arr.len() < 7 {
            continue;
        }
        let Some(ciborium::value::Value::Text(tag)) = arr.get(0) else {
            continue;
        };
        if tag != "ritma-chain@0.1" {
            continue;
        }
        let hour_ts = match arr.get(3) {
            Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
            _ => 0,
        };
        let Some(ciborium::value::Value::Text(hour_root_hex)) = arr.get(5) else {
            continue;
        };
        let Some(hour_root) = decode_32_hex(hour_root_hex) else {
            continue;
        };
        return Ok(Some((hour_ts, hour_root)));
    }
    Ok(None)
}

fn write_hour_root_file(
    shard_dir: &Path,
    shard_id: &str,
    node_id: &str,
    hour_ts: i64,
    micro_count: u64,
    hour_root: [u8; 32],
    prev_hour_root: Option<[u8; 32]>,
) -> std::io::Result<PathBuf> {
    let roots_dir = shard_dir.join("roots");
    std::fs::create_dir_all(&roots_dir)?;
    let path = roots_dir.join("hour.rroot");
    let tmp = roots_dir.join("hour.rroot.tmp");

    let tuple = (
        "ritma-hour-root@0.1",
        shard_id,
        node_id,
        hour_ts,
        micro_count,
        hex::encode(hour_root),
        prev_hour_root.map(hex::encode),
    );

    let mut buf: Vec<u8> = Vec::new();
    ciborium::into_writer(&tuple, &mut buf).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, &buf)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

fn append_chain_record(
    chain_path: &Path,
    shard_id: &str,
    node_id: &str,
    hour_ts: i64,
    prev_hour_root: [u8; 32],
    hour_root: [u8; 32],
) -> std::io::Result<()> {
    let mut h = Sha256::new();
    h.update(b"ritma-chain-hash@0.1");
    h.update(prev_hour_root);
    h.update(hour_root);
    let chain_hash: [u8; 32] = h.finalize().into();

    let entry = (
        "ritma-chain@0.1",
        shard_id,
        node_id,
        hour_ts,
        hex::encode(prev_hour_root),
        hex::encode(hour_root),
        hex::encode(chain_hash),
    );
    append_framed_cbor(chain_path, &entry)
}

fn encode_leb128_u64(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

fn shard_paths(base: &Path, ts: i64) -> (String, PathBuf, PathBuf) {
    let dt = chrono::DateTime::<Utc>::from_timestamp(ts, 0)
        .unwrap_or_else(|| chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap());

    let shard_id = format!(
        "{:04}{:02}{:02}{:02}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour()
    );

    let shard_dir = base
        .join("ledger")
        .join("v2")
        .join("shards")
        .join(format!("{:04}", dt.year()))
        .join(format!("{:02}", dt.month()))
        .join(format!("{:02}", dt.day()))
        .join(format!("{:02}", dt.hour()));

    let segments_dir = shard_dir.join("segments");
    (shard_id, shard_dir, segments_dir)
}

fn segment_bucket_name(ts: i64) -> String {
    let dt = chrono::DateTime::<Utc>::from_timestamp(ts, 0)
        .unwrap_or_else(|| chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap());
    let minute = dt.minute();
    let bucket = (minute / 10) * 10;
    format!("{bucket:02}")
}

fn decode_leb128_u64(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

fn scan_valid_segment_length(path: &Path) -> std::io::Result<u64> {
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() {
        return Ok(0);
    }

    // Segment header is raw CBOR (no LEB128 prefix). Parse it first.
    let header_end = {
        let mut cursor = std::io::Cursor::new(&bytes);
        match ciborium::from_reader::<ciborium::value::Value, _>(&mut cursor) {
            Ok(_) => cursor.position() as usize,
            Err(_) => return Ok(0),
        }
    };

    let mut pos = header_end;
    while pos < bytes.len() {
        let Some((rec_len, leb_size)) = decode_leb128_u64(&bytes[pos..]) else {
            break;
        };
        let rec_end = pos + leb_size + rec_len as usize;
        if rec_end > bytes.len() {
            break;
        }
        // Validate record is parseable CBOR
        let rec_start = pos + leb_size;
        if ciborium::from_reader::<ciborium::value::Value, _>(&bytes[rec_start..rec_end]).is_err() {
            break;
        }
        pos = rec_end;
    }
    Ok(pos as u64)
}

pub fn recover_segment(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let file_len = std::fs::metadata(path)?.len();
    let valid_len = scan_valid_segment_length(path)?;
    if valid_len < file_len {
        let f = OpenOptions::new().write(true).open(path)?;
        f.set_len(valid_len)?;
        f.sync_all()?;
    }
    Ok(())
}

fn ensure_segment_header(
    c: &StorageContract,
    segment_path: &Path,
    shard_id: &str,
    seg_idx: u64,
    start_ts: i64,
) -> std::io::Result<()> {
    if segment_path.exists() {
        // Crash recovery: truncate incomplete tail
        recover_segment(segment_path)?;
        return Ok(());
    }

    if let Some(parent) = segment_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .open(segment_path)?;

    let dt = chrono::DateTime::<Utc>::from_timestamp(start_ts, 0)
        .unwrap_or_else(|| chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap());

    let header = (
        "ritma-seg@1.0",
        2u64,
        dt.to_rfc3339(),
        c.node_id.as_str(),
        shard_id,
        seg_idx,
        Option::<String>::None,
        (),
    );

    ciborium::into_writer(&header, &mut f).map_err(std::io::Error::other)?;
    f.sync_all()?;
    Ok(())
}

/// Write window as RTSL record using v2 Forensic Page Standard.
/// Per spec §2.1: RTSL leaf = SHA-256(0x00 || canonical_cbor(leaf_payload))
/// where leaf_payload contains page_hash, not raw event hashes.
pub fn write_window_v2_as_rtsl_record(
    c: &StorageContract,
    namespace_id: &str,
    window_id: &str,
    start_ts: i64,
    end_ts: i64,
    page_hash: &str,
    total_events: u64,
) -> std::io::Result<PathBuf> {
    let (shard_id, shard_dir, segments_dir) = shard_paths(&c.out_dir, start_ts);
    std::fs::create_dir_all(&segments_dir)?;

    let bucket = segment_bucket_name(start_ts);
    let seg_idx = bucket.parse::<u64>().unwrap_or(0) / 10;
    let segment_path = segments_dir.join(format!("{bucket}.rseg"));

    ensure_segment_header(c, &segment_path, &shard_id, seg_idx, start_ts)?;

    // Compute RTSL v2 leaf hash per spec §2.2: SHA-256(0x00 || canonical_cbor(leaf_payload))
    let leaf_payload = serde_json::json!({
        "v": 2,
        "ns": namespace_id,
        "win_id": window_id,
        "start": start_ts,
        "end": end_ts,
        "page_hash": page_hash
    });
    let mut leaf_cbor = Vec::new();
    ciborium::into_writer(&leaf_payload, &mut leaf_cbor).map_err(std::io::Error::other)?;

    let leaf_hash = {
        let mut h = Sha256::new();
        h.update(&[0x00]); // CT-style leaf domain separator per RFC 9162 §2.1
        h.update(&leaf_cbor);
        let out = h.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(&out);
        b
    };

    let record_id = format!("w2-{}", &hex::encode(&leaf_hash)[..32]);

    let body = (
        "ritma-body@0.2", // v2 body format
        namespace_id,
        c.node_id.as_str(),
        window_id,
        start_ts,
        end_ts,
        total_events,
        page_hash,
        hex::encode(leaf_hash),
    );

    let mut body_buf = Vec::new();
    ciborium::into_writer(&body, &mut body_buf).map_err(std::io::Error::other)?;

    let body_hash = {
        let mut h = Sha256::new();
        h.update(&body_buf);
        let out = h.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(&out);
        b
    };

    let timestamp_ns: i64 = start_ts.saturating_mul(1_000_000_000);

    let header = (
        "ritma-rec@1.0",
        2u64, // v2 record
        record_id.as_str(),
        timestamp_ns,
        body_buf.len() as u64,
        hex::encode(body_hash),
        0u64,
        (),
    );

    let mut rec_buf = Vec::new();
    ciborium::into_writer(&header, &mut rec_buf).map_err(std::io::Error::other)?;
    rec_buf.extend_from_slice(&body_buf);

    let len_prefix = encode_leb128_u64(rec_buf.len() as u64);

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&segment_path)?;
    let offset = f.metadata().map(|m| m.len()).unwrap_or(0);
    f.write_all(&len_prefix)?;
    f.write_all(&rec_buf)?;
    f.sync_all()?;

    let record_len = (len_prefix.len() + rec_buf.len()) as u64;

    let idx_dir = shard_dir.join("index");
    let time_idx = idx_dir.join("time.ridx");

    let time_entry = (
        "ritma-idx-time@0.2",
        &shard_id,
        timestamp_ns,
        bucket.as_str(),
        offset as u64,
        record_len,
        namespace_id,
        hex::encode(leaf_hash),
        page_hash,
    );
    append_framed_cbor(&time_idx, &time_entry)?;

    // Compute hour root and update chain
    let (hour_root, micro_count) = compute_hour_root_from_time_index(&time_idx)?;
    let chain_dir = c.out_dir.join("ledger").join("v2").join("chain");
    std::fs::create_dir_all(&chain_dir)?;
    let chain_path = chain_dir.join("chain.rchn");
    let prev_hour_root = read_prev_hour_root(&chain_path)?;
    let hour_ts = (start_ts / 3600) * 3600;
    let _ = write_hour_root_file(
        &shard_dir,
        &shard_id,
        c.node_id.as_str(),
        hour_ts,
        micro_count,
        hour_root,
        prev_hour_root,
    )?;

    // Optional signing
    let _ = maybe_sign_file(
        &shard_dir.join("roots").join("hour.rroot"),
        &shard_dir.join("roots").join("hour.rroot.sig"),
        "hour_root",
    );

    Ok(segment_path)
}

/// Legacy v1: Write window as RTSL record using event hash merkle root.
/// Deprecated - use write_window_v2_as_rtsl_record for new implementations.
pub fn write_window_as_rtsl_record(
    c: &StorageContract,
    namespace_id: &str,
    start_ts: i64,
    end_ts: i64,
    total_events: u64,
    leaf_hashes: &[[u8; 32]],
) -> std::io::Result<PathBuf> {
    let (shard_id, shard_dir, segments_dir) = shard_paths(&c.out_dir, start_ts);
    std::fs::create_dir_all(&segments_dir)?;

    let bucket = segment_bucket_name(start_ts);
    let seg_idx = bucket.parse::<u64>().unwrap_or(0) / 10;
    let segment_path = segments_dir.join(format!("{bucket}.rseg"));

    ensure_segment_header(c, &segment_path, &shard_id, seg_idx, start_ts)?;

    let micro_root = crate::merkle_root_sha256(leaf_hashes);

    let record_id = {
        let mut h = Sha256::new();
        h.update(b"ritma-rtsl-record-id@0.1");
        h.update(namespace_id.as_bytes());
        h.update(start_ts.to_le_bytes());
        h.update(end_ts.to_le_bytes());
        h.update(total_events.to_le_bytes());
        h.update(micro_root);
        let out = h.finalize();
        format!("w-{}", hex::encode(&out[..16]))
    };

    let body = (
        "ritma-body@0.1",
        namespace_id,
        c.node_id.as_str(),
        start_ts,
        end_ts,
        total_events,
        leaf_hashes.len() as u64,
        hex::encode(micro_root),
    );

    let mut body_buf = Vec::new();
    ciborium::into_writer(&body, &mut body_buf).map_err(std::io::Error::other)?;

    let body_hash = {
        let mut h = Sha256::new();
        h.update(&body_buf);
        let out = h.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(&out);
        b
    };

    let timestamp_ns: i64 = start_ts.saturating_mul(1_000_000_000);

    let header = (
        "ritma-rec@1.0",
        1u64,
        record_id.as_str(),
        timestamp_ns,
        body_buf.len() as u64,
        hex::encode(body_hash),
        0u64,
        (),
    );

    let mut rec_buf = Vec::new();
    ciborium::into_writer(&header, &mut rec_buf).map_err(std::io::Error::other)?;
    rec_buf.extend_from_slice(&body_buf);

    let len_prefix = encode_leb128_u64(rec_buf.len() as u64);

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&segment_path)?;
    let offset = f.metadata().map(|m| m.len()).unwrap_or(0);
    f.write_all(&len_prefix)?;
    f.write_all(&rec_buf)?;
    f.sync_all()?;

    let record_len = (len_prefix.len() + rec_buf.len()) as u64;

    let idx_dir = shard_dir.join("index");
    let time_idx = idx_dir.join("time.ridx");
    let object_idx = idx_dir.join("object.ridx");

    let time_entry = (
        "ritma-idx-time@0.1",
        &shard_id,
        timestamp_ns,
        bucket.as_str(),
        offset as u64,
        record_len,
        namespace_id,
        hex::encode(micro_root),
    );
    append_framed_cbor(&time_idx, &time_entry)?;

    let object_entry = (
        "ritma-idx-object@0.1",
        &shard_id,
        namespace_id,
        timestamp_ns,
        bucket.as_str(),
        offset as u64,
        record_len,
    );
    append_framed_cbor(&object_idx, &object_entry)?;

    // Hash index: content-addressable lookup by micro_root and body_hash
    let hash_idx = idx_dir.join("hash.ridx");
    let hash_entry = (
        "ritma-idx-hash@0.1",
        &shard_id,
        hex::encode(micro_root),
        hex::encode(body_hash),
        bucket.as_str(),
        offset as u64,
        record_len,
        namespace_id,
        timestamp_ns,
    );
    append_framed_cbor(&hash_idx, &hash_entry)?;

    // Roots + chain (unsigned v0)
    let (hour_root, micro_count) = compute_hour_root_from_time_index(&time_idx)?;
    let chain_dir = c.out_dir.join("ledger").join("v2").join("chain");
    std::fs::create_dir_all(&chain_dir)?;
    let chain_path = chain_dir.join("chain.rchn");
    let prev_hour_root = read_prev_hour_root(&chain_path)?;
    let hour_ts = (start_ts / 3600) * 3600;
    let _ = write_hour_root_file(
        &shard_dir,
        &shard_id,
        c.node_id.as_str(),
        hour_ts,
        micro_count,
        hour_root,
        prev_hour_root,
    )?;

    // Optional signing for hour root
    let _ = maybe_sign_file(
        &shard_dir.join("roots").join("hour.rroot"),
        &shard_dir.join("roots").join("hour.rroot.sig"),
        "hour_root",
    );

    let prev_for_chain = prev_hour_root.unwrap_or_else(|| {
        let mut h = Sha256::new();
        h.update(b"GENESIS");
        h.finalize().into()
    });

    // Chain is hour-level: append at most once per hour boundary.
    // During the hour, hour.rroot may be updated as more windows arrive.
    let last = read_last_chain_entry(&chain_path)?;
    let should_append = match last {
        Some((last_hour_ts, _)) => last_hour_ts != hour_ts,
        None => true,
    };
    if should_append {
        append_chain_record(
            &chain_path,
            &shard_id,
            c.node_id.as_str(),
            hour_ts,
            prev_for_chain,
            hour_root,
        )?;

        // Optional signing for chain head
        let _ = maybe_sign_file(&chain_path, &chain_dir.join("chain.rchn.sig"), "chain_head");
    }

    Ok(segment_path)
}

// ============================================================================
// Advanced Data Structures Integration
// ============================================================================

/// RTSL Ledger with advanced Merkle structures
/// Combines MMR for chain, tiled Merkle for hour roots, and vector clocks for causality
pub struct RtslLedger {
    /// Node ID for this writer
    pub node_id: String,
    /// MMR for global chain of hour roots
    pub chain_mmr: MerkleMountainRange,
    /// Tiled Merkle tree for current hour's micro-windows
    pub hour_tree: TiledMerkleTree,
    /// Vector clock for causal ordering across nodes
    pub vclock: VectorClock,
    /// Current hour timestamp (floor to hour)
    pub current_hour_ts: i64,
}

impl RtslLedger {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            chain_mmr: MerkleMountainRange::new(),
            hour_tree: TiledMerkleTree::new(),
            vclock: VectorClock::new(),
            current_hour_ts: 0,
        }
    }

    /// Record a micro-window and update structures
    pub fn record_window(&mut self, micro_root: [u8; 32], timestamp: i64) -> WindowReceipt {
        let hour_ts = (timestamp / 3600) * 3600;

        // Check if we crossed an hour boundary
        if hour_ts != self.current_hour_ts && self.current_hour_ts != 0 {
            // Finalize previous hour
            let hour_root = self.hour_tree.root_hash();
            self.chain_mmr.append(hour_root);
            self.hour_tree = TiledMerkleTree::new();
        }
        self.current_hour_ts = hour_ts;

        // Add to current hour's tree
        self.hour_tree.append(micro_root);

        // Increment vector clock
        self.vclock.increment(&self.node_id);

        WindowReceipt {
            micro_root,
            timestamp,
            hour_ts,
            tree_size: self.hour_tree.size,
            vclock: self.vclock.clone(),
            chain_size: self.chain_mmr.size,
        }
    }

    /// Get current hour root
    pub fn current_hour_root(&self) -> [u8; 32] {
        self.hour_tree.root_hash()
    }

    /// Get global chain root (MMR root)
    pub fn chain_root(&self) -> [u8; 32] {
        self.chain_mmr.root()
    }

    /// Get MMR peaks for the chain
    pub fn chain_peaks(&self) -> Vec<[u8; 32]> {
        self.chain_mmr.peaks().to_vec()
    }

    /// Merge vector clock from another node (for distributed coordination)
    pub fn merge_clock(&mut self, other: &VectorClock) {
        self.vclock.merge(other);
    }

    /// Serialize ledger state for persistence
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Node ID
        let node_bytes = self.node_id.as_bytes();
        buf.extend_from_slice(&(node_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(node_bytes);

        // Current hour timestamp
        buf.extend_from_slice(&self.current_hour_ts.to_le_bytes());

        // Vector clock
        let vclock_bytes = self.vclock.to_bytes();
        buf.extend_from_slice(&(vclock_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&vclock_bytes);

        // MMR size and peaks
        buf.extend_from_slice(&self.chain_mmr.size.to_le_bytes());
        let peaks = self.chain_mmr.peaks();
        buf.extend_from_slice(&(peaks.len() as u32).to_le_bytes());
        for peak in peaks {
            buf.extend_from_slice(peak);
        }

        // Hour tree size and root
        buf.extend_from_slice(&self.hour_tree.size.to_le_bytes());
        buf.extend_from_slice(&self.hour_tree.root_hash());

        buf
    }
}

/// Receipt for a recorded window
#[derive(Debug, Clone)]
pub struct WindowReceipt {
    pub micro_root: [u8; 32],
    pub timestamp: i64,
    pub hour_ts: i64,
    pub tree_size: u64,
    pub vclock: VectorClock,
    pub chain_size: u64,
}

impl WindowReceipt {
    /// Generate a deterministic receipt ID
    pub fn receipt_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"rtsl-receipt@0.1");
        h.update(&self.micro_root);
        h.update(&self.timestamp.to_le_bytes());
        h.update(&self.tree_size.to_le_bytes());
        let out = h.finalize();
        format!("rcpt-{}", hex::encode(&out[..16]))
    }
}

/// Causal record with vector clock metadata
#[derive(Debug, Clone)]
pub struct CausalRecord {
    pub record_id: String,
    pub node_id: String,
    pub timestamp_ns: i64,
    pub vclock: VectorClock,
    pub data_hash: [u8; 32],
    pub prev_hash: Option<[u8; 32]>,
}

impl CausalRecord {
    pub fn new(node_id: &str, timestamp_ns: i64, data_hash: [u8; 32], vclock: VectorClock) -> Self {
        let record_id = {
            let mut h = Sha256::new();
            h.update(b"causal-record@0.1");
            h.update(node_id.as_bytes());
            h.update(&timestamp_ns.to_le_bytes());
            h.update(&data_hash);
            let out = h.finalize();
            format!("cr-{}", hex::encode(&out[..16]))
        };

        Self {
            record_id,
            node_id: node_id.to_string(),
            timestamp_ns,
            vclock,
            data_hash,
            prev_hash: None,
        }
    }

    /// Check if this record happened-before another
    pub fn happened_before(&self, other: &CausalRecord) -> bool {
        self.vclock.happened_before(&other.vclock)
    }

    /// Check if records are concurrent
    pub fn concurrent_with(&self, other: &CausalRecord) -> bool {
        self.vclock.concurrent(&other.vclock)
    }

    /// Serialize to CBOR bytes
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-causal@0.1",
            &self.record_id,
            &self.node_id,
            self.timestamp_ns,
            hex::encode(self.data_hash),
            self.prev_hash.map(hex::encode),
            self.vclock.to_bytes(),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn set_env(name: &str, value: &str) -> Option<String> {
        let prev = std::env::var(name).ok();
        std::env::set_var(name, value);
        prev
    }

    fn restore_env(name: &str, prev: Option<String>) {
        match prev {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }

    fn read_first_frame(path: &Path) -> (u32, ciborium::value::Value) {
        let bytes = std::fs::read(path).expect("read");
        assert!(bytes.len() >= 4);
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[..4]);
        let len = u32::from_le_bytes(len_bytes);
        let start = 4;
        let end = start + len as usize;
        let v =
            ciborium::from_reader::<ciborium::value::Value, _>(&bytes[start..end]).expect("cbor");
        (len, v)
    }

    #[test]
    fn rtsl_writes_segment_and_indexes() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("ritma_contract_rtsl_test_{now}"));
        let _ = std::fs::create_dir_all(&base);
        let out_dir = base.join("RITMA_OUT");

        // Signatures test needs env vars; guard against parallel test races.
        let _guard = env_lock().lock().unwrap();
        let keystore_path = base.join("node_keystore.json");
        let keystore_json = r#"[{"key_id":"k1","alg":"ed25519","secret_hex":"0000000000000000000000000000000000000000000000000000000000000000"}]"#;
        std::fs::write(&keystore_path, keystore_json).expect("write keystore");

        let prev_key_id = set_env("RITMA_KEY_ID", "k1");
        let prev_keystore = set_env(
            "RITMA_KEYSTORE_PATH",
            keystore_path.to_string_lossy().as_ref(),
        );
        let prev_sign = set_env("RITMA_OUT_RTSL_SIGN", "1");
        let c = StorageContract {
            node_id: "node:test".to_string(),
            base_dir: base.clone(),
            index_db_path: base.join("index_db.sqlite"),
            out_dir: out_dir.clone(),
            lock_dir: base.join("locks"),
            lock_path: base.join("locks").join("x.lock"),
        };

        c.ensure_out_layout().expect("layout");

        let leaf_hashes: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let seg =
            write_window_as_rtsl_record(&c, "ns://t", 1700000000, 1700000300, 7, &leaf_hashes)
                .expect("write");
        assert!(seg.exists());

        let (_shard_id, shard_dir, _segments_dir) = shard_paths(&c.out_dir, 1700000000);
        let time_idx = shard_dir.join("index").join("time.ridx");
        let object_idx = shard_dir.join("index").join("object.ridx");
        let hash_idx = shard_dir.join("index").join("hash.ridx");
        assert!(time_idx.exists());
        assert!(object_idx.exists());
        assert!(hash_idx.exists());

        let (_len, v) = read_first_frame(&time_idx);
        let ciborium::value::Value::Array(arr) = v else {
            panic!("expected array");
        };
        assert!(
            matches!(arr.get(0), Some(ciborium::value::Value::Text(t)) if t == "ritma-idx-time@0.1")
        );

        let (_len2, v2) = read_first_frame(&object_idx);
        let ciborium::value::Value::Array(arr2) = v2 else {
            panic!("expected array");
        };
        assert!(
            matches!(arr2.get(0), Some(ciborium::value::Value::Text(t)) if t == "ritma-idx-object@0.1")
        );

        let (_shard_id, shard_dir, _segments_dir) = shard_paths(&c.out_dir, 1700000000);
        let hour_root_path = shard_dir.join("roots").join("hour.rroot");
        assert!(hour_root_path.exists());

        let chain_path = c
            .out_dir
            .join("ledger")
            .join("v2")
            .join("chain")
            .join("chain.rchn");
        assert!(chain_path.exists());
        let frames = read_framed_cbor(&chain_path).expect("frames");
        assert!(!frames.is_empty());

        let hour_sig = shard_dir.join("roots").join("hour.rroot.sig");
        assert!(hour_sig.exists());
        let chain_sig = c
            .out_dir
            .join("ledger")
            .join("v2")
            .join("chain")
            .join("chain.rchn.sig");
        assert!(chain_sig.exists());

        // restore env
        restore_env("RITMA_KEY_ID", prev_key_id);
        restore_env("RITMA_KEYSTORE_PATH", prev_keystore);
        restore_env("RITMA_OUT_RTSL_SIGN", prev_sign);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn rtsl_crash_recovery_truncates_incomplete_tail() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("ritma_crash_test_{now}"));
        let _ = std::fs::create_dir_all(&base);

        let seg_path = base.join("test.rseg");

        // Write a valid segment header
        {
            let header = (
                "ritma-seg@1.0",
                2u64,
                "2023-11-14T00:00:00Z",
                "node:x",
                "2023111400",
                0u64,
                Option::<String>::None,
                (),
            );
            let mut f = std::fs::File::create(&seg_path).unwrap();
            ciborium::into_writer(&header, &mut f).unwrap();
            f.sync_all().unwrap();
        }
        let header_len = std::fs::metadata(&seg_path).unwrap().len();

        // Append a valid LEB128-framed record
        let rec_body = ("ritma-rec@1.0", 1u64, "rec-1");
        let mut rec_buf = Vec::new();
        ciborium::into_writer(&rec_body, &mut rec_buf).unwrap();
        let leb = encode_leb128_u64(rec_buf.len() as u64);
        {
            let mut f = OpenOptions::new().append(true).open(&seg_path).unwrap();
            f.write_all(&leb).unwrap();
            f.write_all(&rec_buf).unwrap();
            f.sync_all().unwrap();
        }
        let valid_len = std::fs::metadata(&seg_path).unwrap().len();

        // Append garbage (incomplete record)
        {
            let mut f = OpenOptions::new().append(true).open(&seg_path).unwrap();
            f.write_all(&[0x80, 0x80, 0x01, 0xDE, 0xAD]).unwrap(); // bad LEB + junk
            f.sync_all().unwrap();
        }
        let corrupted_len = std::fs::metadata(&seg_path).unwrap().len();
        assert!(corrupted_len > valid_len);

        // Run recovery
        recover_segment(&seg_path).unwrap();

        let recovered_len = std::fs::metadata(&seg_path).unwrap().len();
        assert_eq!(
            recovered_len, valid_len,
            "should truncate to last valid record"
        );
        assert!(recovered_len > header_len, "should keep header + record");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_rtsl_ledger_with_advanced_structures() {
        let mut ledger = RtslLedger::new("node1".to_string());

        // Record some windows
        let ts1 = 1700000000i64;
        let root1 = [1u8; 32];
        let receipt1 = ledger.record_window(root1, ts1);

        assert_eq!(receipt1.tree_size, 1);
        assert_eq!(receipt1.hour_ts, (ts1 / 3600) * 3600);
        assert!(!receipt1.receipt_id().is_empty());

        // Record another in same hour
        let root2 = [2u8; 32];
        let receipt2 = ledger.record_window(root2, ts1 + 60);
        assert_eq!(receipt2.tree_size, 2);

        // Hour root should be non-zero
        let hour_root = ledger.current_hour_root();
        assert_ne!(hour_root, [0u8; 32]);

        // Cross hour boundary
        let ts2 = ts1 + 3600; // next hour
        let root3 = [3u8; 32];
        let receipt3 = ledger.record_window(root3, ts2);

        // Chain should have grown (previous hour finalized)
        assert_eq!(receipt3.chain_size, 1);
        assert_eq!(receipt3.tree_size, 1); // new hour tree

        // Chain root should be non-zero
        let chain_root = ledger.chain_root();
        assert_ne!(chain_root, [0u8; 32]);

        // Serialize and check
        let bytes = ledger.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_causal_record_ordering() {
        let mut vc1 = VectorClock::new();
        vc1.increment("node1");

        let mut vc2 = VectorClock::new();
        vc2.increment("node1");
        vc2.increment("node1");

        let rec1 = CausalRecord::new("node1", 1000, [1u8; 32], vc1);
        let rec2 = CausalRecord::new("node1", 2000, [2u8; 32], vc2);

        // rec1 happened before rec2
        assert!(rec1.happened_before(&rec2));
        assert!(!rec2.happened_before(&rec1));

        // Concurrent records
        let mut vc3 = VectorClock::new();
        vc3.increment("node2");
        let rec3 = CausalRecord::new("node2", 1500, [3u8; 32], vc3);

        assert!(rec1.concurrent_with(&rec3));

        // CBOR serialization
        let cbor = rec1.to_cbor();
        assert!(!cbor.is_empty());
    }
}
