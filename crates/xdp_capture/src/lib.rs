//! XDP-based Full Packet Capture (Q1.1)
//!
//! High-performance packet capture using XDP (eXpress Data Path) for:
//! - Zero-copy packet capture at line rate
//! - Selective capture based on flow rules
//! - Ring buffer for efficient kernel-to-userspace transfer
//! - PCAP-NG export for forensic analysis

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum XdpCaptureError {
    #[error("XDP not available: {0}")]
    NotAvailable(String),
    #[error("capture failed: {0}")]
    CaptureFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ring buffer overflow")]
    RingBufferOverflow,
}

/// Capture mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Capture all packets (high volume)
    Full,
    /// Capture only packet headers (efficient)
    HeadersOnly,
    /// Capture based on filter rules
    Filtered,
    /// Sample packets (1 in N)
    Sampled,
}

impl Default for CaptureMode {
    fn default() -> Self {
        Self::HeadersOnly
    }
}

/// Capture filter rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureFilter {
    pub filter_id: String,
    pub protocol: Option<Protocol>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub direction: Direction,
    pub action: FilterAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Ingress,
    Egress,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Capture,
    Skip,
    Sample,
}

/// Captured packet metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMeta {
    pub packet_id: [u8; 32],
    pub timestamp_ns: u64,
    pub interface: String,
    pub direction: Direction,
    pub protocol: Protocol,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub packet_len: u32,
    pub captured_len: u32,
    pub payload_hash: [u8; 32],
    pub flags: PacketFlags,
}

impl PacketMeta {
    pub fn compute_id(timestamp_ns: u64, src_ip: &str, dst_ip: &str, payload: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-pkt@0.1");
        h.update(timestamp_ns.to_le_bytes());
        h.update(src_ip.as_bytes());
        h.update(b"\x00");
        h.update(dst_ip.as_bytes());
        h.update(b"\x00");
        h.update(payload);
        h.finalize().into()
    }

    pub fn packet_id_hex(&self) -> String {
        hex::encode(self.packet_id)
    }
}

/// Packet flags
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PacketFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub truncated: bool,
    pub fragmented: bool,
}

/// Captured packet with optional payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPacket {
    pub meta: PacketMeta,
    pub payload: Option<Vec<u8>>,
}

impl CapturedPacket {
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Capture statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureStats {
    pub packets_received: u64,
    pub packets_captured: u64,
    pub packets_dropped: u64,
    pub bytes_received: u64,
    pub bytes_captured: u64,
    pub ring_buffer_overflows: u64,
    pub filter_matches: u64,
    pub start_time: i64,
    pub last_packet_time: i64,
}

/// Ring buffer for packet capture
pub struct PacketRingBuffer {
    capacity: usize,
    packets: std::collections::VecDeque<CapturedPacket>,
    overflow_count: u64,
}

impl PacketRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            packets: std::collections::VecDeque::with_capacity(capacity),
            overflow_count: 0,
        }
    }

    pub fn push(&mut self, packet: CapturedPacket) -> bool {
        if self.packets.len() >= self.capacity {
            self.packets.pop_front();
            self.packets.push_back(packet);
            self.overflow_count += 1;
            false
        } else {
            self.packets.push_back(packet);
            true
        }
    }

    pub fn drain(&mut self) -> Vec<CapturedPacket> {
        self.packets.drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }
}

/// XDP capture session
pub struct XdpCaptureSession {
    session_id: String,
    interface: String,
    mode: CaptureMode,
    filters: Vec<CaptureFilter>,
    ring_buffer: PacketRingBuffer,
    stats: CaptureStats,
    output_dir: PathBuf,
    sample_rate: u32,
    max_packet_size: u32,
}

impl XdpCaptureSession {
    pub fn new(interface: &str, output_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(output_dir)?;

        Ok(Self {
            session_id: format!("xdp_{}", uuid::Uuid::new_v4()),
            interface: interface.to_string(),
            mode: CaptureMode::default(),
            filters: Vec::new(),
            ring_buffer: PacketRingBuffer::new(10000),
            stats: CaptureStats {
                start_time: chrono::Utc::now().timestamp(),
                ..Default::default()
            },
            output_dir: output_dir.to_path_buf(),
            sample_rate: 1,
            max_packet_size: 65535,
        })
    }

    pub fn with_mode(mut self, mode: CaptureMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_sample_rate(mut self, rate: u32) -> Self {
        self.sample_rate = rate.max(1);
        self
    }

    pub fn with_max_packet_size(mut self, size: u32) -> Self {
        self.max_packet_size = size;
        self
    }

    pub fn add_filter(&mut self, filter: CaptureFilter) {
        self.filters.push(filter);
    }

    /// Check if packet matches any filter
    fn matches_filter(&self, meta: &PacketMeta) -> bool {
        if self.filters.is_empty() {
            return true;
        }

        for filter in &self.filters {
            let mut matches = true;

            if let Some(ref proto) = filter.protocol {
                if *proto != Protocol::Any && *proto != meta.protocol {
                    matches = false;
                }
            }

            if let Some(ref src) = filter.src_ip {
                if !meta.src_ip.starts_with(src) {
                    matches = false;
                }
            }

            if let Some(ref dst) = filter.dst_ip {
                if !meta.dst_ip.starts_with(dst) {
                    matches = false;
                }
            }

            if let Some(port) = filter.src_port {
                if meta.src_port != port {
                    matches = false;
                }
            }

            if let Some(port) = filter.dst_port {
                if meta.dst_port != port {
                    matches = false;
                }
            }

            if matches {
                return filter.action == FilterAction::Capture;
            }
        }

        false
    }

    /// Process a raw packet (called from XDP ring buffer)
    pub fn process_packet(
        &mut self,
        timestamp_ns: u64,
        direction: Direction,
        raw_packet: &[u8],
    ) -> Option<PacketMeta> {
        self.stats.packets_received += 1;
        self.stats.bytes_received += raw_packet.len() as u64;

        // Parse packet headers
        let meta = self.parse_packet(timestamp_ns, direction, raw_packet)?;

        // Check filter
        if !self.matches_filter(&meta) {
            return None;
        }

        // Sample if needed
        if self.mode == CaptureMode::Sampled {
            if self.stats.packets_received % self.sample_rate as u64 != 0 {
                return None;
            }
        }

        self.stats.filter_matches += 1;

        // Capture packet
        let captured_len = match self.mode {
            CaptureMode::HeadersOnly => raw_packet.len().min(64) as u32,
            CaptureMode::Full => raw_packet.len().min(self.max_packet_size as usize) as u32,
            _ => raw_packet.len().min(self.max_packet_size as usize) as u32,
        };

        let payload = if self.mode == CaptureMode::HeadersOnly {
            None
        } else {
            Some(raw_packet[..captured_len as usize].to_vec())
        };

        let packet = CapturedPacket {
            meta: PacketMeta {
                captured_len,
                ..meta.clone()
            },
            payload,
        };

        if !self.ring_buffer.push(packet) {
            self.stats.ring_buffer_overflows += 1;
        }

        self.stats.packets_captured += 1;
        self.stats.bytes_captured += captured_len as u64;
        self.stats.last_packet_time = chrono::Utc::now().timestamp();

        Some(meta)
    }

    /// Parse raw packet into metadata
    fn parse_packet(
        &self,
        timestamp_ns: u64,
        direction: Direction,
        raw: &[u8],
    ) -> Option<PacketMeta> {
        if raw.len() < 14 {
            return None; // Too short for Ethernet
        }

        // Skip Ethernet header (14 bytes)
        let ip_start = 14;
        if raw.len() < ip_start + 20 {
            return None; // Too short for IP
        }

        let version = (raw[ip_start] >> 4) & 0x0F;
        if version != 4 {
            return None; // Only IPv4 for now
        }

        let ihl = (raw[ip_start] & 0x0F) as usize * 4;
        let protocol_byte = raw[ip_start + 9];
        let src_ip = format!(
            "{}.{}.{}.{}",
            raw[ip_start + 12],
            raw[ip_start + 13],
            raw[ip_start + 14],
            raw[ip_start + 15]
        );
        let dst_ip = format!(
            "{}.{}.{}.{}",
            raw[ip_start + 16],
            raw[ip_start + 17],
            raw[ip_start + 18],
            raw[ip_start + 19]
        );

        let (protocol, src_port, dst_port, flags) = if raw.len() >= ip_start + ihl + 4 {
            let transport_start = ip_start + ihl;
            let src_port = u16::from_be_bytes([raw[transport_start], raw[transport_start + 1]]);
            let dst_port = u16::from_be_bytes([raw[transport_start + 2], raw[transport_start + 3]]);

            let (proto, flags) = match protocol_byte {
                6 => {
                    // TCP
                    let tcp_flags = if raw.len() >= transport_start + 14 {
                        let f = raw[transport_start + 13];
                        PacketFlags {
                            fin: f & 0x01 != 0,
                            syn: f & 0x02 != 0,
                            rst: f & 0x04 != 0,
                            psh: f & 0x08 != 0,
                            ack: f & 0x10 != 0,
                            urg: f & 0x20 != 0,
                            ..Default::default()
                        }
                    } else {
                        PacketFlags::default()
                    };
                    (Protocol::Tcp, tcp_flags)
                }
                17 => (Protocol::Udp, PacketFlags::default()),
                1 => (Protocol::Icmp, PacketFlags::default()),
                _ => (Protocol::Any, PacketFlags::default()),
            };

            (proto, src_port, dst_port, flags)
        } else {
            (Protocol::Any, 0, 0, PacketFlags::default())
        };

        let payload_hash = blake3::hash(raw).into();
        let packet_id = PacketMeta::compute_id(timestamp_ns, &src_ip, &dst_ip, raw);

        Some(PacketMeta {
            packet_id,
            timestamp_ns,
            interface: self.interface.clone(),
            direction,
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packet_len: raw.len() as u32,
            captured_len: raw.len() as u32,
            payload_hash,
            flags,
        })
    }

    /// Flush captured packets to disk
    pub fn flush(&mut self) -> std::io::Result<PathBuf> {
        let packets = self.ring_buffer.drain();
        if packets.is_empty() {
            return Ok(self.output_dir.clone());
        }

        let now = chrono::Utc::now();
        let filename = format!(
            "capture_{}_{}.cbor.zst",
            now.format("%Y%m%d_%H%M%S"),
            &self.session_id[..8]
        );
        let path = self.output_dir.join(&filename);

        let mut buf = Vec::new();
        ciborium::into_writer(&packets, &mut buf).map_err(std::io::Error::other)?;
        let compressed = zstd::encode_all(&buf[..], 3).map_err(std::io::Error::other)?;
        std::fs::write(&path, compressed)?;

        Ok(path)
    }

    /// Get capture statistics
    pub fn stats(&self) -> &CaptureStats {
        &self.stats
    }

    /// Get session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Export to PCAP-NG format
    pub fn export_pcapng(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;

        let mut file = std::fs::File::create(path)?;

        // Section Header Block
        let shb = PcapngSectionHeader::new();
        file.write_all(&shb.to_bytes())?;

        // Interface Description Block
        let idb = PcapngInterfaceDesc::new(&self.interface);
        file.write_all(&idb.to_bytes())?;

        // Enhanced Packet Blocks
        for packet in &self.ring_buffer.packets {
            let epb = PcapngEnhancedPacket::from_captured(packet);
            file.write_all(&epb.to_bytes())?;
        }

        Ok(())
    }
}

// PCAP-NG structures for export

struct PcapngSectionHeader;

impl PcapngSectionHeader {
    fn new() -> Self {
        Self
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Block Type: Section Header Block (0x0A0D0D0A)
        buf.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
        // Block Total Length (minimum 28)
        buf.extend_from_slice(&28u32.to_le_bytes());
        // Byte-Order Magic
        buf.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        // Major Version
        buf.extend_from_slice(&1u16.to_le_bytes());
        // Minor Version
        buf.extend_from_slice(&0u16.to_le_bytes());
        // Section Length (-1 = unspecified)
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        // Block Total Length (repeated)
        buf.extend_from_slice(&28u32.to_le_bytes());
        buf
    }
}

struct PcapngInterfaceDesc {
    name: String,
}

impl PcapngInterfaceDesc {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Block Type: Interface Description Block (0x00000001)
        buf.extend_from_slice(&1u32.to_le_bytes());
        // Block Total Length (minimum 20 + options)
        let total_len = 20u32;
        buf.extend_from_slice(&total_len.to_le_bytes());
        // LinkType: Ethernet (1)
        buf.extend_from_slice(&1u16.to_le_bytes());
        // Reserved
        buf.extend_from_slice(&0u16.to_le_bytes());
        // SnapLen
        buf.extend_from_slice(&65535u32.to_le_bytes());
        // Block Total Length (repeated)
        buf.extend_from_slice(&total_len.to_le_bytes());
        buf
    }
}

struct PcapngEnhancedPacket {
    timestamp_ns: u64,
    captured_len: u32,
    original_len: u32,
    data: Vec<u8>,
}

impl PcapngEnhancedPacket {
    fn from_captured(packet: &CapturedPacket) -> Self {
        Self {
            timestamp_ns: packet.meta.timestamp_ns,
            captured_len: packet.meta.captured_len,
            original_len: packet.meta.packet_len,
            data: packet.payload.clone().unwrap_or_default(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Block Type: Enhanced Packet Block (0x00000006)
        buf.extend_from_slice(&6u32.to_le_bytes());

        // Pad data to 4-byte boundary
        let padded_len = (self.data.len() + 3) & !3;
        let total_len = 32 + padded_len as u32;

        buf.extend_from_slice(&total_len.to_le_bytes());
        // Interface ID
        buf.extend_from_slice(&0u32.to_le_bytes());
        // Timestamp (high)
        buf.extend_from_slice(&((self.timestamp_ns >> 32) as u32).to_le_bytes());
        // Timestamp (low)
        buf.extend_from_slice(&(self.timestamp_ns as u32).to_le_bytes());
        // Captured Packet Length
        buf.extend_from_slice(&self.captured_len.to_le_bytes());
        // Original Packet Length
        buf.extend_from_slice(&self.original_len.to_le_bytes());
        // Packet Data
        buf.extend_from_slice(&self.data);
        // Padding
        buf.resize(buf.len() + (padded_len - self.data.len()), 0);
        // Block Total Length (repeated)
        buf.extend_from_slice(&total_len.to_le_bytes());
        buf
    }
}

/// Flow tracker for connection-level analysis
pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
    max_flows: usize,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    protocol: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowState {
    pub flow_id: String,
    pub start_time: i64,
    pub last_seen: i64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub state: TcpState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    New,
    SynSent,
    SynReceived,
    Established,
    FinWait,
    Closed,
}

impl FlowTracker {
    pub fn new(max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
        }
    }

    pub fn track_packet(&mut self, meta: &PacketMeta) -> Option<&FlowState> {
        let key = FlowKey {
            src_ip: meta.src_ip.clone(),
            src_port: meta.src_port,
            dst_ip: meta.dst_ip.clone(),
            dst_port: meta.dst_port,
            protocol: match meta.protocol {
                Protocol::Tcp => 6,
                Protocol::Udp => 17,
                Protocol::Icmp => 1,
                Protocol::Any => 0,
            },
        };

        let now = chrono::Utc::now().timestamp();

        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_seen = now;
            match meta.direction {
                Direction::Ingress => {
                    flow.packets_in += 1;
                    flow.bytes_in += meta.packet_len as u64;
                }
                Direction::Egress | Direction::Both => {
                    flow.packets_out += 1;
                    flow.bytes_out += meta.packet_len as u64;
                }
            }

            // Update TCP state
            if meta.protocol == Protocol::Tcp {
                let current_state = flow.state;
                flow.state = Self::update_tcp_state_static(current_state, &meta.flags);
            }

            return self.flows.get(&key);
        }

        // Create new flow
        if self.flows.len() >= self.max_flows {
            // Evict oldest flow
            let oldest = self
                .flows
                .iter()
                .min_by_key(|(_, f)| f.last_seen)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.flows.remove(&k);
            }
        }

        let flow = FlowState {
            flow_id: format!("flow_{}", uuid::Uuid::new_v4()),
            start_time: now,
            last_seen: now,
            packets_in: if meta.direction == Direction::Ingress {
                1
            } else {
                0
            },
            packets_out: if meta.direction != Direction::Ingress {
                1
            } else {
                0
            },
            bytes_in: if meta.direction == Direction::Ingress {
                meta.packet_len as u64
            } else {
                0
            },
            bytes_out: if meta.direction != Direction::Ingress {
                meta.packet_len as u64
            } else {
                0
            },
            state: if meta.flags.syn {
                TcpState::SynSent
            } else {
                TcpState::New
            },
        };

        self.flows.insert(key.clone(), flow);
        self.flows.get(&key)
    }

    fn update_tcp_state_static(current: TcpState, flags: &PacketFlags) -> TcpState {
        match current {
            TcpState::New if flags.syn => TcpState::SynSent,
            TcpState::SynSent if flags.syn && flags.ack => TcpState::SynReceived,
            TcpState::SynReceived if flags.ack => TcpState::Established,
            TcpState::Established if flags.fin => TcpState::FinWait,
            TcpState::FinWait if flags.ack => TcpState::Closed,
            _ if flags.rst => TcpState::Closed,
            _ => current,
        }
    }

    pub fn get_active_flows(&self) -> Vec<&FlowState> {
        self.flows.values().collect()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_ring_buffer() {
        let mut buf = PacketRingBuffer::new(3);

        let make_packet = |id: u8| CapturedPacket {
            meta: PacketMeta {
                packet_id: [id; 32],
                timestamp_ns: id as u64 * 1000,
                interface: "eth0".to_string(),
                direction: Direction::Ingress,
                protocol: Protocol::Tcp,
                src_ip: "192.168.1.1".to_string(),
                src_port: 12345,
                dst_ip: "10.0.0.1".to_string(),
                dst_port: 80,
                packet_len: 100,
                captured_len: 100,
                payload_hash: [0; 32],
                flags: PacketFlags::default(),
            },
            payload: None,
        };

        assert!(buf.push(make_packet(1)));
        assert!(buf.push(make_packet(2)));
        assert!(buf.push(make_packet(3)));
        // 4th push causes overflow - oldest is evicted, new one added
        assert!(!buf.push(make_packet(4))); // Returns false because overflow occurred

        assert_eq!(buf.overflow_count(), 1);
        // After overflow, we still have 3 items (evicted 1, added 1)
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn test_flow_tracker() {
        let mut tracker = FlowTracker::new(100);

        let meta = PacketMeta {
            packet_id: [0; 32],
            timestamp_ns: 1000,
            interface: "eth0".to_string(),
            direction: Direction::Egress,
            protocol: Protocol::Tcp,
            src_ip: "192.168.1.1".to_string(),
            src_port: 12345,
            dst_ip: "10.0.0.1".to_string(),
            dst_port: 80,
            packet_len: 100,
            captured_len: 100,
            payload_hash: [0; 32],
            flags: PacketFlags {
                syn: true,
                ..Default::default()
            },
        };

        let flow = tracker.track_packet(&meta);
        assert!(flow.is_some());
        assert_eq!(flow.unwrap().state, TcpState::SynSent);
        assert_eq!(tracker.flow_count(), 1);
    }

    #[test]
    fn test_capture_filter() {
        let tmp = std::env::temp_dir().join("xdp_test");
        let mut session = XdpCaptureSession::new("eth0", &tmp).unwrap();

        session.add_filter(CaptureFilter {
            filter_id: "f1".to_string(),
            protocol: Some(Protocol::Tcp),
            src_ip: None,
            dst_ip: Some("10.0.0".to_string()),
            src_port: None,
            dst_port: Some(80),
            direction: Direction::Both,
            action: FilterAction::Capture,
        });

        let meta = PacketMeta {
            packet_id: [0; 32],
            timestamp_ns: 1000,
            interface: "eth0".to_string(),
            direction: Direction::Egress,
            protocol: Protocol::Tcp,
            src_ip: "192.168.1.1".to_string(),
            src_port: 12345,
            dst_ip: "10.0.0.1".to_string(),
            dst_port: 80,
            packet_len: 100,
            captured_len: 100,
            payload_hash: [0; 32],
            flags: PacketFlags::default(),
        };

        assert!(session.matches_filter(&meta));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
