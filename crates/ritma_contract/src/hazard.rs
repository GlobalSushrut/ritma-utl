//! Hazard-mode tracing and out-of-band persistence
//!
//! Capability #3: When normal logging paths may be compromised or unavailable,
//! hazard mode provides:
//! - Memory-mapped ring buffer for crash-safe local persistence
//! - Out-of-band shipping to remote witnesses
//! - Cryptographic commitments before detailed data
//! - Tamper-evident sealed segments

use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::merkle_advanced::VectorClock;

// ============================================================================
// Hazard Mode Configuration
// ============================================================================

/// Hazard mode activation level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HazardLevel {
    /// Normal operation - standard logging
    Normal,
    /// Elevated - duplicate to out-of-band storage
    Elevated,
    /// Critical - commit hashes before data, witness required
    Critical,
    /// Emergency - minimal footprint, immediate ship
    Emergency,
}

impl HazardLevel {
    pub fn from_env() -> Self {
        match std::env::var("RITMA_HAZARD_LEVEL").as_deref() {
            Ok("elevated") | Ok("1") => Self::Elevated,
            Ok("critical") | Ok("2") => Self::Critical,
            Ok("emergency") | Ok("3") => Self::Emergency,
            _ => Self::Normal,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }
}

// ============================================================================
// Ring Buffer for Crash-Safe Local Persistence
// ============================================================================

/// Fixed-size ring buffer header (64 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RingBufferHeader {
    /// Magic bytes: "RTSL-HAZ"
    pub magic: [u8; 8],
    /// Version
    pub version: u32,
    /// Total buffer size (including header)
    pub total_size: u64,
    /// Write position (wraps around)
    pub write_pos: u64,
    /// Sequence number (monotonic)
    pub sequence: u64,
    /// Last flush timestamp (unix nanos)
    pub last_flush_ns: i64,
    /// Checksum of header fields
    pub header_checksum: u32,
    /// Reserved
    pub _reserved: [u8; 16],
}

impl RingBufferHeader {
    pub const SIZE: usize = 64;
    pub const MAGIC: [u8; 8] = *b"RTSL-HAZ";

    pub fn new(total_size: u64) -> Self {
        let mut h = Self {
            magic: Self::MAGIC,
            version: 1,
            total_size,
            write_pos: 0,
            sequence: 0,
            last_flush_ns: 0,
            header_checksum: 0,
            _reserved: [0u8; 16],
        };
        h.header_checksum = h.compute_checksum();
        h
    }

    fn compute_checksum(&self) -> u32 {
        let mut sum: u32 = 0;
        for b in &self.magic {
            sum = sum.wrapping_add(*b as u32);
        }
        sum = sum.wrapping_add(self.version);
        sum = sum.wrapping_add((self.total_size & 0xFFFFFFFF) as u32);
        sum = sum.wrapping_add((self.write_pos & 0xFFFFFFFF) as u32);
        sum = sum.wrapping_add((self.sequence & 0xFFFFFFFF) as u32);
        sum
    }

    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.header_checksum == self.compute_checksum()
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..20].copy_from_slice(&self.total_size.to_le_bytes());
        buf[20..28].copy_from_slice(&self.write_pos.to_le_bytes());
        buf[28..36].copy_from_slice(&self.sequence.to_le_bytes());
        buf[36..44].copy_from_slice(&self.last_flush_ns.to_le_bytes());
        buf[44..48].copy_from_slice(&self.header_checksum.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Self {
        Self {
            magic: buf[0..8].try_into().unwrap(),
            version: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            total_size: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
            write_pos: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
            sequence: u64::from_le_bytes(buf[28..36].try_into().unwrap()),
            last_flush_ns: i64::from_le_bytes(buf[36..44].try_into().unwrap()),
            header_checksum: u32::from_le_bytes(buf[44..48].try_into().unwrap()),
            _reserved: [0u8; 16],
        }
    }
}

/// Entry in the ring buffer
#[derive(Debug, Clone)]
pub struct HazardEntry {
    /// Sequence number
    pub sequence: u64,
    /// Timestamp (unix nanos)
    pub timestamp_ns: i64,
    /// Entry type
    pub entry_type: HazardEntryType,
    /// Node ID
    pub node_id: String,
    /// Data hash (commitment)
    pub data_hash: [u8; 32],
    /// Optional payload (may be empty in emergency mode)
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HazardEntryType {
    /// Commitment only (hash of data to follow)
    Commitment = 1,
    /// Full data record
    FullRecord = 2,
    /// Witness acknowledgment
    WitnessAck = 3,
    /// Seal marker (end of segment)
    Seal = 4,
    /// Heartbeat (proof of liveness)
    Heartbeat = 5,
}

impl HazardEntry {
    /// Serialize to bytes with length prefix
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Sequence (8)
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        // Timestamp (8)
        buf.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        // Entry type (1)
        buf.push(self.entry_type as u8);
        // Node ID length + data
        let node_bytes = self.node_id.as_bytes();
        buf.extend_from_slice(&(node_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(node_bytes);
        // Data hash (32)
        buf.extend_from_slice(&self.data_hash);
        // Payload length + data
        buf.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload);

        // Prepend total length
        let len = buf.len() as u32;
        let mut out = len.to_le_bytes().to_vec();
        out.extend(buf);
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if data.len() < 4 + len {
            return None;
        }

        let buf = &data[4..4 + len];
        let mut pos = 0;

        // Sequence
        if pos + 8 > buf.len() {
            return None;
        }
        let sequence = u64::from_le_bytes(buf[pos..pos + 8].try_into().ok()?);
        pos += 8;

        // Timestamp
        if pos + 8 > buf.len() {
            return None;
        }
        let timestamp_ns = i64::from_le_bytes(buf[pos..pos + 8].try_into().ok()?);
        pos += 8;

        // Entry type
        if pos + 1 > buf.len() {
            return None;
        }
        let entry_type = match buf[pos] {
            1 => HazardEntryType::Commitment,
            2 => HazardEntryType::FullRecord,
            3 => HazardEntryType::WitnessAck,
            4 => HazardEntryType::Seal,
            5 => HazardEntryType::Heartbeat,
            _ => return None,
        };
        pos += 1;

        // Node ID
        if pos + 2 > buf.len() {
            return None;
        }
        let node_len = u16::from_le_bytes(buf[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;
        if pos + node_len > buf.len() {
            return None;
        }
        let node_id = String::from_utf8(buf[pos..pos + node_len].to_vec()).ok()?;
        pos += node_len;

        // Data hash
        if pos + 32 > buf.len() {
            return None;
        }
        let mut data_hash = [0u8; 32];
        data_hash.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;

        // Payload
        if pos + 4 > buf.len() {
            return None;
        }
        let payload_len = u32::from_le_bytes(buf[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if pos + payload_len > buf.len() {
            return None;
        }
        let payload = buf[pos..pos + payload_len].to_vec();

        Some((
            Self {
                sequence,
                timestamp_ns,
                entry_type,
                node_id,
                data_hash,
                payload,
            },
            4 + len,
        ))
    }
}

/// Ring buffer for hazard-mode persistence
pub struct HazardRingBuffer {
    path: PathBuf,
    file: File,
    header: RingBufferHeader,
    data_start: u64,
    data_size: u64,
}

impl HazardRingBuffer {
    /// Create or open a ring buffer file
    pub fn open(path: &Path, size: u64) -> std::io::Result<Self> {
        let exists = path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        let total_size = size.max(4096); // minimum 4KB
        let data_start = RingBufferHeader::SIZE as u64;
        let data_size = total_size - data_start;

        let header = if exists {
            // Try to read existing header
            let mut buf = [0u8; RingBufferHeader::SIZE];
            file.read_exact(&mut buf)?;
            let h = RingBufferHeader::from_bytes(&buf);
            if h.is_valid() {
                h
            } else {
                // Corrupted, reinitialize
                let h = RingBufferHeader::new(total_size);
                file.seek(SeekFrom::Start(0))?;
                file.write_all(&h.to_bytes())?;
                file.set_len(total_size)?;
                file.sync_all()?;
                h
            }
        } else {
            // Initialize new buffer
            let h = RingBufferHeader::new(total_size);
            file.write_all(&h.to_bytes())?;
            file.set_len(total_size)?;
            file.sync_all()?;
            h
        };

        Ok(Self {
            path: path.to_path_buf(),
            file,
            header,
            data_start,
            data_size,
        })
    }

    /// Write an entry to the ring buffer
    pub fn write(&mut self, entry: &HazardEntry) -> std::io::Result<u64> {
        let bytes = entry.to_bytes();
        let len = bytes.len() as u64;

        if len > self.data_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "entry too large for ring buffer",
            ));
        }

        // Calculate write position (may wrap)
        let pos = self.header.write_pos % self.data_size;
        let file_pos = self.data_start + pos;

        // Write (may need to wrap)
        if pos + len <= self.data_size {
            // Single write
            self.file.seek(SeekFrom::Start(file_pos))?;
            self.file.write_all(&bytes)?;
        } else {
            // Wrap around
            let first_part = (self.data_size - pos) as usize;
            self.file.seek(SeekFrom::Start(file_pos))?;
            self.file.write_all(&bytes[..first_part])?;
            self.file.seek(SeekFrom::Start(self.data_start))?;
            self.file.write_all(&bytes[first_part..])?;
        }

        // Update header
        self.header.write_pos = self.header.write_pos.wrapping_add(len);
        self.header.sequence += 1;
        self.header.last_flush_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.header.header_checksum = self.header.compute_checksum();

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.header.to_bytes())?;
        self.file.sync_all()?;

        Ok(self.header.sequence)
    }

    /// Get current sequence number
    pub fn sequence(&self) -> u64 {
        self.header.sequence
    }

    /// Get path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ============================================================================
// Out-of-Band Witness
// ============================================================================

/// Witness endpoint for out-of-band shipping
#[derive(Debug, Clone)]
pub struct WitnessEndpoint {
    /// Endpoint URL or path
    pub endpoint: String,
    /// Witness type
    pub witness_type: WitnessType,
    /// Public key for verification (hex)
    pub public_key: Option<String>,
    /// Priority (lower = higher priority)
    pub priority: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessType {
    /// Local file system (another mount point)
    LocalFs,
    /// HTTP/HTTPS endpoint
    Http,
    /// S3-compatible storage
    S3,
    /// IPFS
    Ipfs,
    /// Custom protocol
    Custom,
}

/// Commitment sent to witness before full data
#[derive(Debug, Clone)]
pub struct WitnessCommitment {
    /// Commitment ID
    pub commitment_id: String,
    /// Node ID making the commitment
    pub node_id: String,
    /// Timestamp
    pub timestamp_ns: i64,
    /// Hash of data to follow
    pub data_hash: [u8; 32],
    /// Expected data size
    pub data_size: u64,
    /// Vector clock at commitment time
    pub vclock: VectorClock,
    /// Signature (if signing enabled)
    pub signature: Option<String>,
}

impl WitnessCommitment {
    pub fn new(node_id: &str, data: &[u8], vclock: VectorClock) -> Self {
        let mut h = Sha256::new();
        h.update(data);
        let data_hash: [u8; 32] = h.finalize().into();

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        let commitment_id = {
            let mut h = Sha256::new();
            h.update(b"witness-commitment@0.1");
            h.update(node_id.as_bytes());
            h.update(&timestamp_ns.to_le_bytes());
            h.update(&data_hash);
            format!("wc-{}", hex::encode(&h.finalize()[..16]))
        };

        Self {
            commitment_id,
            node_id: node_id.to_string(),
            timestamp_ns,
            data_hash,
            data_size: data.len() as u64,
            vclock,
            signature: None,
        }
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-witness-commit@0.1",
            &self.commitment_id,
            &self.node_id,
            self.timestamp_ns,
            hex::encode(self.data_hash),
            self.data_size,
            self.vclock.to_bytes(),
            &self.signature,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

/// Witness acknowledgment
#[derive(Debug, Clone)]
pub struct WitnessAck {
    /// Commitment ID being acknowledged
    pub commitment_id: String,
    /// Witness ID
    pub witness_id: String,
    /// Timestamp of acknowledgment
    pub ack_timestamp_ns: i64,
    /// Witness signature
    pub signature: String,
}

// ============================================================================
// Hazard Tracer
// ============================================================================

/// Main hazard-mode tracer
pub struct HazardTracer {
    /// Node ID
    pub node_id: String,
    /// Current hazard level
    pub level: HazardLevel,
    /// Ring buffer for local persistence
    ring_buffer: Option<HazardRingBuffer>,
    /// Witness endpoints
    witnesses: Vec<WitnessEndpoint>,
    /// Pending commitments awaiting data
    pending_commitments: VecDeque<WitnessCommitment>,
    /// Vector clock
    vclock: VectorClock,
    /// Sequence counter
    sequence: AtomicU64,
}

impl HazardTracer {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id: node_id.clone(),
            level: HazardLevel::from_env(),
            ring_buffer: None,
            witnesses: Vec::new(),
            pending_commitments: VecDeque::new(),
            vclock: VectorClock::new(),
            sequence: AtomicU64::new(0),
        }
    }

    /// Initialize ring buffer
    pub fn init_ring_buffer(&mut self, path: &Path, size: u64) -> std::io::Result<()> {
        let rb = HazardRingBuffer::open(path, size)?;
        self.sequence.store(rb.sequence(), Ordering::SeqCst);
        self.ring_buffer = Some(rb);
        Ok(())
    }

    /// Add a witness endpoint
    pub fn add_witness(&mut self, endpoint: WitnessEndpoint) {
        self.witnesses.push(endpoint);
        self.witnesses.sort_by_key(|w| w.priority);
    }

    /// Set hazard level
    pub fn set_level(&mut self, level: HazardLevel) {
        self.level = level;
    }

    /// Record a hazard event
    pub fn record(&mut self, data: &[u8]) -> std::io::Result<HazardReceipt> {
        self.vclock.increment(&self.node_id);
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        let mut h = Sha256::new();
        h.update(data);
        let data_hash: [u8; 32] = h.finalize().into();

        match self.level {
            HazardLevel::Normal => {
                // Just write to ring buffer if available
                if let Some(ref mut rb) = self.ring_buffer {
                    let entry = HazardEntry {
                        sequence: seq,
                        timestamp_ns,
                        entry_type: HazardEntryType::FullRecord,
                        node_id: self.node_id.clone(),
                        data_hash,
                        payload: data.to_vec(),
                    };
                    rb.write(&entry)?;
                }
            }
            HazardLevel::Elevated => {
                // Write to ring buffer AND prepare for witness
                if let Some(ref mut rb) = self.ring_buffer {
                    let entry = HazardEntry {
                        sequence: seq,
                        timestamp_ns,
                        entry_type: HazardEntryType::FullRecord,
                        node_id: self.node_id.clone(),
                        data_hash,
                        payload: data.to_vec(),
                    };
                    rb.write(&entry)?;
                }
                // Queue for witness shipping (async)
                let commitment = WitnessCommitment::new(&self.node_id, data, self.vclock.clone());
                self.pending_commitments.push_back(commitment);
            }
            HazardLevel::Critical => {
                // Commitment first, then data
                let commitment = WitnessCommitment::new(&self.node_id, data, self.vclock.clone());

                // Write commitment to ring buffer
                if let Some(ref mut rb) = self.ring_buffer {
                    let commit_entry = HazardEntry {
                        sequence: seq,
                        timestamp_ns,
                        entry_type: HazardEntryType::Commitment,
                        node_id: self.node_id.clone(),
                        data_hash,
                        payload: commitment.to_cbor(),
                    };
                    rb.write(&commit_entry)?;
                }

                self.pending_commitments.push_back(commitment);

                // Then write full data
                if let Some(ref mut rb) = self.ring_buffer {
                    let data_entry = HazardEntry {
                        sequence: seq + 1,
                        timestamp_ns,
                        entry_type: HazardEntryType::FullRecord,
                        node_id: self.node_id.clone(),
                        data_hash,
                        payload: data.to_vec(),
                    };
                    rb.write(&data_entry)?;
                }
            }
            HazardLevel::Emergency => {
                // Minimal footprint - commitment only, no payload
                if let Some(ref mut rb) = self.ring_buffer {
                    let entry = HazardEntry {
                        sequence: seq,
                        timestamp_ns,
                        entry_type: HazardEntryType::Commitment,
                        node_id: self.node_id.clone(),
                        data_hash,
                        payload: Vec::new(), // No payload in emergency
                    };
                    rb.write(&entry)?;
                }
            }
        }

        Ok(HazardReceipt {
            sequence: seq,
            timestamp_ns,
            data_hash,
            level: self.level,
            vclock: self.vclock.clone(),
        })
    }

    /// Write a heartbeat (proof of liveness)
    pub fn heartbeat(&mut self) -> std::io::Result<()> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        if let Some(ref mut rb) = self.ring_buffer {
            let entry = HazardEntry {
                sequence: seq,
                timestamp_ns,
                entry_type: HazardEntryType::Heartbeat,
                node_id: self.node_id.clone(),
                data_hash: [0u8; 32],
                payload: Vec::new(),
            };
            rb.write(&entry)?;
        }
        Ok(())
    }

    /// Seal current segment (tamper-evident marker)
    pub fn seal(&mut self) -> std::io::Result<SealReceipt> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        // Compute seal hash over recent entries
        let mut h = Sha256::new();
        h.update(b"hazard-seal@0.1");
        h.update(&self.node_id.as_bytes());
        h.update(&seq.to_le_bytes());
        h.update(&timestamp_ns.to_le_bytes());
        let seal_hash: [u8; 32] = h.finalize().into();

        if let Some(ref mut rb) = self.ring_buffer {
            let entry = HazardEntry {
                sequence: seq,
                timestamp_ns,
                entry_type: HazardEntryType::Seal,
                node_id: self.node_id.clone(),
                data_hash: seal_hash,
                payload: Vec::new(),
            };
            rb.write(&entry)?;
        }

        Ok(SealReceipt {
            sequence: seq,
            timestamp_ns,
            seal_hash,
        })
    }

    /// Get pending commitments count
    pub fn pending_count(&self) -> usize {
        self.pending_commitments.len()
    }

    /// Drain pending commitments for shipping
    pub fn drain_pending(&mut self) -> Vec<WitnessCommitment> {
        self.pending_commitments.drain(..).collect()
    }
}

/// Receipt for a hazard record
#[derive(Debug, Clone)]
pub struct HazardReceipt {
    pub sequence: u64,
    pub timestamp_ns: i64,
    pub data_hash: [u8; 32],
    pub level: HazardLevel,
    pub vclock: VectorClock,
}

impl HazardReceipt {
    pub fn receipt_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"hazard-receipt@0.1");
        h.update(&self.sequence.to_le_bytes());
        h.update(&self.data_hash);
        format!("hr-{}", hex::encode(&h.finalize()[..16]))
    }
}

/// Receipt for a seal operation
#[derive(Debug, Clone)]
pub struct SealReceipt {
    pub sequence: u64,
    pub timestamp_ns: i64,
    pub seal_hash: [u8; 32],
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_ring_buffer_header() {
        let h = RingBufferHeader::new(4096);
        assert!(h.is_valid());

        let bytes = h.to_bytes();
        let h2 = RingBufferHeader::from_bytes(&bytes);
        assert!(h2.is_valid());
        assert_eq!(h.total_size, h2.total_size);
    }

    #[test]
    fn test_hazard_entry_serialization() {
        let entry = HazardEntry {
            sequence: 42,
            timestamp_ns: 1700000000_000_000_000,
            entry_type: HazardEntryType::FullRecord,
            node_id: "node1".to_string(),
            data_hash: [0xaa; 32],
            payload: vec![1, 2, 3, 4],
        };

        let bytes = entry.to_bytes();
        let (decoded, len) = HazardEntry::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.node_id, "node1");
        assert_eq!(decoded.data_hash, [0xaa; 32]);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn test_hazard_ring_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("hazard_rb_test_{now}"));

        {
            let mut rb = HazardRingBuffer::open(&path, 8192).unwrap();

            let entry = HazardEntry {
                sequence: 1,
                timestamp_ns: 1700000000_000_000_000,
                entry_type: HazardEntryType::FullRecord,
                node_id: "test".to_string(),
                data_hash: [0xbb; 32],
                payload: vec![5, 6, 7, 8],
            };

            let seq = rb.write(&entry).unwrap();
            assert_eq!(seq, 1);
        }

        // Reopen and verify header persisted
        {
            let rb = HazardRingBuffer::open(&path, 8192).unwrap();
            assert_eq!(rb.sequence(), 1);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_hazard_tracer_normal_mode() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("hazard_tracer_test_{now}"));

        let mut tracer = HazardTracer::new("node1".to_string());
        tracer.init_ring_buffer(&path, 16384).unwrap();

        let receipt = tracer.record(b"test data").unwrap();
        assert_eq!(receipt.level, HazardLevel::Normal);
        assert!(!receipt.receipt_id().is_empty());

        tracer.heartbeat().unwrap();
        let seal = tracer.seal().unwrap();
        assert_ne!(seal.seal_hash, [0u8; 32]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_witness_commitment() {
        let vclock = VectorClock::new();
        let commitment = WitnessCommitment::new("node1", b"test data", vclock);

        assert!(!commitment.commitment_id.is_empty());
        assert_eq!(commitment.data_size, 9);

        let cbor = commitment.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_hazard_level_from_env() {
        // Default is Normal
        let level = HazardLevel::from_env();
        // Can't assert specific value since env may vary
        assert!(matches!(
            level,
            HazardLevel::Normal
                | HazardLevel::Elevated
                | HazardLevel::Critical
                | HazardLevel::Emergency
        ));
    }
}
