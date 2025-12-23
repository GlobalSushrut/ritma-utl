use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkAnalysisError {
    #[error("Deep packet inspection failed: {0}")]
    DpiError(String),
    #[error("Protocol anomaly detected: {0}")]
    ProtocolAnomalyError(String),
    #[error("Traffic fingerprinting failed: {0}")]
    FingerprintingError(String),
}

pub type Result<T> = std::result::Result<T, NetworkAnalysisError>;

/// Deep packet inspection alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub protocol: String,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub description: String,
    pub evidence: DpiEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Exploit,
    CommandAndControl,
    DataExfiltration,
    LateralMovement,
    PortScan,
    DnsExfiltration,
    TunnelDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiEvidence {
    pub payload_hash: String,
    pub suspicious_patterns: Vec<String>,
    pub matched_signatures: Vec<String>,
    pub packet_count: u64,
    pub byte_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Protocol anomaly alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAnomalyAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub protocol: String,
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub description: String,
    pub baseline_deviation: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    UnusualPacketSize,
    UnusualFrequency,
    MalformedPacket,
    UnexpectedFlags,
    ProtocolViolation,
    TimingAnomaly,
}

/// Encrypted traffic fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTrafficFingerprint {
    pub fingerprint_id: String,
    pub timestamp: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub ja3_hash: Option<String>,  // TLS client fingerprint
    pub ja3s_hash: Option<String>, // TLS server fingerprint
    pub packet_timing: Vec<u64>,
    pub packet_sizes: Vec<usize>,
    pub application_guess: Option<String>,
    pub is_suspicious: bool,
    pub suspicious_reasons: Vec<String>,
}

/// Network flow
#[derive(Debug, Clone)]
pub struct NetworkFlow {
    pub flow_id: String,
    pub source_ip: String,
    pub source_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    pub start_time: i64,
    pub last_seen: i64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub packets: VecDeque<PacketInfo>,
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: i64,
    pub size: usize,
    pub flags: Vec<String>,
    pub payload_hash: Option<String>,
}

/// Deep packet inspector
pub struct DeepPacketInspector {
    /// Malware signatures
    signatures: HashMap<String, Vec<u8>>,

    /// DPI alerts
    alerts: Vec<DpiAlert>,

    /// Known C2 patterns
    c2_patterns: Vec<String>,
}

impl DeepPacketInspector {
    pub fn new() -> Self {
        let mut inspector = Self {
            signatures: HashMap::new(),
            alerts: Vec::new(),
            c2_patterns: Vec::new(),
        };

        // Load default C2 patterns
        inspector.c2_patterns = vec![
            "POST /gate.php".to_string(),
            "GET /admin/get.php".to_string(),
            "/c2/beacon".to_string(),
            "/api/v1/tasks".to_string(),
        ];

        inspector
    }

    /// Add malware signature
    pub fn add_signature(&mut self, name: String, signature: Vec<u8>) {
        self.signatures.insert(name, signature);
    }

    /// Inspect packet payload
    pub fn inspect_payload(
        &mut self,
        source_ip: String,
        dest_ip: String,
        protocol: String,
        payload: &[u8],
    ) -> Option<DpiAlert> {
        let payload_hash = format!("{:x}", sha2::Sha256::digest(payload));
        let mut matched_signatures = Vec::new();
        let mut suspicious_patterns = Vec::new();

        // Check for malware signatures
        for (name, sig) in &self.signatures {
            if payload
                .windows(sig.len())
                .any(|window| window == sig.as_slice())
            {
                matched_signatures.push(name.clone());
            }
        }

        // Check for C2 patterns
        let payload_str = String::from_utf8_lossy(payload);
        for pattern in &self.c2_patterns {
            if payload_str.contains(pattern) {
                suspicious_patterns.push(pattern.clone());
            }
        }

        // Check for shellcode patterns
        if self.contains_shellcode(payload) {
            suspicious_patterns.push("Shellcode detected".to_string());
        }

        // Generate alert if threats found
        if !matched_signatures.is_empty() || !suspicious_patterns.is_empty() {
            let alert = DpiAlert {
                alert_id: format!("dpi_{}", uuid::Uuid::new_v4()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                source_ip: source_ip.clone(),
                dest_ip: dest_ip.clone(),
                protocol: protocol.clone(),
                threat_type: if !matched_signatures.is_empty() {
                    ThreatType::Malware
                } else {
                    ThreatType::CommandAndControl
                },
                severity: Severity::Critical,
                description: format!("Malicious payload detected from {source_ip} to {dest_ip}"),
                evidence: DpiEvidence {
                    payload_hash,
                    suspicious_patterns,
                    matched_signatures,
                    packet_count: 1,
                    byte_count: payload.len() as u64,
                },
            };

            log::error!("🔴 DPI ALERT: Malicious payload detected");
            self.alerts.push(alert.clone());
            return Some(alert);
        }

        None
    }

    /// Check for shellcode patterns
    fn contains_shellcode(&self, payload: &[u8]) -> bool {
        // Common shellcode patterns
        let patterns: Vec<&[u8]> = vec![
            &[0x90, 0x90, 0x90, 0x90], // NOP sled
            &[0xeb, 0xfe],             // JMP $
            &[0x31, 0xc0],             // XOR EAX, EAX
            &[0x48, 0x31, 0xff],       // XOR RDI, RDI (x64)
        ];

        for pattern in &patterns {
            if payload.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }

        false
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[DpiAlert] {
        &self.alerts
    }
}

impl Default for DeepPacketInspector {
    fn default() -> Self {
        Self::new()
    }
}

/// Protocol anomaly detector
pub struct ProtocolAnomalyDetector {
    /// Protocol baselines
    baselines: HashMap<String, ProtocolBaseline>,

    /// Anomaly alerts
    alerts: Vec<ProtocolAnomalyAlert>,
}

#[derive(Debug, Clone)]
struct ProtocolBaseline {
    avg_packet_size: f64,
    avg_frequency: f64,
    std_dev_size: f64,
    std_dev_frequency: f64,
    sample_count: u64,
}

impl ProtocolAnomalyDetector {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Learn baseline for a protocol
    pub fn learn_baseline(
        &mut self,
        protocol: String,
        packet_sizes: &[usize],
        frequencies: &[f64],
    ) {
        let avg_size = packet_sizes.iter().sum::<usize>() as f64 / packet_sizes.len() as f64;
        let avg_freq = frequencies.iter().sum::<f64>() / frequencies.len() as f64;

        let variance_size: f64 = packet_sizes
            .iter()
            .map(|&s| {
                let diff = s as f64 - avg_size;
                diff * diff
            })
            .sum::<f64>()
            / packet_sizes.len() as f64;

        let variance_freq: f64 = frequencies
            .iter()
            .map(|&f| {
                let diff = f - avg_freq;
                diff * diff
            })
            .sum::<f64>()
            / frequencies.len() as f64;

        let baseline = ProtocolBaseline {
            avg_packet_size: avg_size,
            avg_frequency: avg_freq,
            std_dev_size: variance_size.sqrt(),
            std_dev_frequency: variance_freq.sqrt(),
            sample_count: packet_sizes.len() as u64,
        };

        let sample_count = baseline.sample_count;

        log::info!(
            "Learned baseline for {protocol}: samples={sample_count} avg_size={avg_size:.2}, avg_freq={avg_freq:.2}"
        );
        self.baselines.insert(protocol, baseline);
    }

    /// Detect anomalies
    pub fn detect_anomaly(
        &mut self,
        protocol: &str,
        packet_size: usize,
        frequency: f64,
    ) -> Option<ProtocolAnomalyAlert> {
        if let Some(baseline) = self.baselines.get(protocol) {
            let size_deviation =
                ((packet_size as f64 - baseline.avg_packet_size) / baseline.std_dev_size).abs();
            let freq_deviation =
                ((frequency - baseline.avg_frequency) / baseline.std_dev_frequency).abs();

            // Alert if more than 3 standard deviations
            if size_deviation > 3.0 || freq_deviation > 3.0 {
                let alert = ProtocolAnomalyAlert {
                    alert_id: format!("anomaly_{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    protocol: protocol.to_string(),
                    anomaly_type: if size_deviation > 3.0 {
                        AnomalyType::UnusualPacketSize
                    } else {
                        AnomalyType::UnusualFrequency
                    },
                    severity: Severity::High,
                    description: format!(
                        "Protocol anomaly detected: {protocol} (size_dev: {size_deviation:.2}, freq_dev: {freq_deviation:.2})"
                    ),
                    baseline_deviation: size_deviation.max(freq_deviation),
                };

                log::warn!("🟠 PROTOCOL ANOMALY: {}", alert.description);
                self.alerts.push(alert.clone());
                return Some(alert);
            }
        }

        None
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[ProtocolAnomalyAlert] {
        &self.alerts
    }
}

impl Default for ProtocolAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypted traffic fingerprinter
pub struct EncryptedTrafficFingerprinter {
    /// Known application fingerprints
    known_fingerprints: HashMap<String, String>,

    /// Suspicious fingerprints
    suspicious_fingerprints: Vec<EncryptedTrafficFingerprint>,
}

impl EncryptedTrafficFingerprinter {
    pub fn new() -> Self {
        let mut fingerprinter = Self {
            known_fingerprints: HashMap::new(),
            suspicious_fingerprints: Vec::new(),
        };

        // Load known application JA3 hashes
        fingerprinter.known_fingerprints.insert(
            "771,4865-4866-4867,0-23-65281,29-23-24,0".to_string(),
            "Chrome".to_string(),
        );
        fingerprinter.known_fingerprints.insert(
            "771,4865-4867,0-23-65281,29-23-24,0".to_string(),
            "Firefox".to_string(),
        );

        fingerprinter
    }

    /// Fingerprint encrypted traffic
    pub fn fingerprint_traffic(
        &mut self,
        source_ip: String,
        dest_ip: String,
        tls_version: Option<String>,
        cipher_suite: Option<String>,
        packet_timing: Vec<u64>,
        packet_sizes: Vec<usize>,
    ) -> EncryptedTrafficFingerprint {
        // Generate JA3 hash (simplified)
        let ja3_hash = self.generate_ja3_hash(&tls_version, &cipher_suite);

        // Guess application
        let application_guess = self.known_fingerprints.get(&ja3_hash).cloned();

        // Check for suspicious patterns
        let mut is_suspicious = false;
        let mut suspicious_reasons = Vec::new();

        // Unknown application
        if application_guess.is_none() {
            is_suspicious = true;
            suspicious_reasons.push("Unknown TLS fingerprint".to_string());
        }

        // Unusual packet timing (potential covert channel)
        if self.has_unusual_timing(&packet_timing) {
            is_suspicious = true;
            suspicious_reasons.push("Unusual packet timing pattern".to_string());
        }

        // Unusual packet sizes (potential data exfiltration)
        if self.has_unusual_sizes(&packet_sizes) {
            is_suspicious = true;
            suspicious_reasons.push("Unusual packet size distribution".to_string());
        }

        let fingerprint = EncryptedTrafficFingerprint {
            fingerprint_id: format!("fp_{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_ip: source_ip.clone(),
            dest_ip: dest_ip.clone(),
            tls_version,
            cipher_suite,
            ja3_hash: Some(ja3_hash),
            ja3s_hash: None,
            packet_timing,
            packet_sizes,
            application_guess,
            is_suspicious,
            suspicious_reasons: suspicious_reasons.clone(),
        };

        if is_suspicious {
            log::warn!(
                "🟠 SUSPICIOUS ENCRYPTED TRAFFIC: {source_ip} -> {dest_ip} (reasons: {suspicious_reasons:?})"
            );
            self.suspicious_fingerprints.push(fingerprint.clone());
        }

        fingerprint
    }

    /// Generate JA3 hash (simplified)
    fn generate_ja3_hash(
        &self,
        tls_version: &Option<String>,
        cipher_suite: &Option<String>,
    ) -> String {
        format!(
            "{:x}",
            sha2::Sha256::digest(format!("{tls_version:?}{cipher_suite:?}").as_bytes())
        )
    }

    /// Check for unusual timing patterns
    fn has_unusual_timing(&self, timing: &[u64]) -> bool {
        if timing.len() < 2 {
            return false;
        }

        // Check for highly regular intervals (potential covert channel)
        let intervals: Vec<u64> = timing.windows(2).map(|w| w[1] - w[0]).collect();

        if intervals.is_empty() {
            return false;
        }

        let avg = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;
        let variance: f64 = intervals
            .iter()
            .map(|&i| {
                let diff = i as f64 - avg;
                diff * diff
            })
            .sum::<f64>()
            / intervals.len() as f64;

        let std_dev = variance.sqrt();
        let coefficient_of_variation = std_dev / avg;

        // Very low variation suggests covert channel
        coefficient_of_variation < 0.1
    }

    /// Check for unusual packet sizes
    fn has_unusual_sizes(&self, sizes: &[usize]) -> bool {
        if sizes.is_empty() {
            return false;
        }

        // Check for highly uniform sizes (potential data exfiltration)
        let unique_sizes: std::collections::HashSet<_> = sizes.iter().collect();
        let uniformity = unique_sizes.len() as f64 / sizes.len() as f64;

        // Very low uniformity suggests data exfiltration
        uniformity < 0.2
    }

    /// Get suspicious fingerprints
    pub fn get_suspicious_fingerprints(&self) -> &[EncryptedTrafficFingerprint] {
        &self.suspicious_fingerprints
    }
}

impl Default for EncryptedTrafficFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

/// Main network analysis manager
pub struct NetworkAnalysisManager {
    dpi: DeepPacketInspector,
    anomaly_detector: ProtocolAnomalyDetector,
    fingerprinter: EncryptedTrafficFingerprinter,
}

impl NetworkAnalysisManager {
    pub fn new() -> Self {
        Self {
            dpi: DeepPacketInspector::new(),
            anomaly_detector: ProtocolAnomalyDetector::new(),
            fingerprinter: EncryptedTrafficFingerprinter::new(),
        }
    }

    /// Get DPI
    pub fn dpi(&mut self) -> &mut DeepPacketInspector {
        &mut self.dpi
    }

    /// Get anomaly detector
    pub fn anomaly_detector(&mut self) -> &mut ProtocolAnomalyDetector {
        &mut self.anomaly_detector
    }

    /// Get fingerprinter
    pub fn fingerprinter(&mut self) -> &mut EncryptedTrafficFingerprinter {
        &mut self.fingerprinter
    }

    /// Get comprehensive network analysis report
    pub fn get_analysis_report(&self) -> NetworkAnalysisReport {
        NetworkAnalysisReport {
            dpi_alerts: self.dpi.get_alerts().to_vec(),
            anomaly_alerts: self.anomaly_detector.get_alerts().to_vec(),
            suspicious_fingerprints: self.fingerprinter.get_suspicious_fingerprints().to_vec(),
        }
    }
}

impl Default for NetworkAnalysisManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysisReport {
    pub dpi_alerts: Vec<DpiAlert>,
    pub anomaly_alerts: Vec<ProtocolAnomalyAlert>,
    pub suspicious_fingerprints: Vec<EncryptedTrafficFingerprint>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpi_malware_detection() {
        let mut dpi = DeepPacketInspector::new();

        dpi.add_signature("test_malware".to_string(), vec![0xde, 0xad, 0xbe, 0xef]);

        let payload = vec![0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x02];
        let alert = dpi.inspect_payload(
            "192.168.1.100".to_string(),
            "10.0.0.1".to_string(),
            "TCP".to_string(),
            &payload,
        );

        assert!(alert.is_some());
    }

    #[test]
    fn test_protocol_anomaly_detection() {
        let mut detector = ProtocolAnomalyDetector::new();

        detector.learn_baseline(
            "HTTP".to_string(),
            &[100, 110, 90, 105, 95],
            &[1.0, 1.1, 0.9, 1.05, 0.95],
        );

        let alert = detector.detect_anomaly("HTTP", 5000, 1.0);
        assert!(alert.is_some());
    }

    #[test]
    fn test_encrypted_traffic_fingerprinting() {
        let mut fingerprinter = EncryptedTrafficFingerprinter::new();

        let fingerprint = fingerprinter.fingerprint_traffic(
            "192.168.1.100".to_string(),
            "1.2.3.4".to_string(),
            Some("TLS1.3".to_string()),
            Some("AES256".to_string()),
            vec![1000, 1100, 1200, 1300],
            vec![100, 100, 100, 100],
        );

        assert!(fingerprint.is_suspicious);
    }
}
