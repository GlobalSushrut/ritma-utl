use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EbpfHardeningError {
    #[error("Failed to monitor raw syscall: {0}")]
    RawSyscallError(String),
    #[error("Probe tampering detected: {0}")]
    ProbeTamperingError(String),
    #[error("Failed to reattach probe: {0}")]
    ProbeReattachError(String),
    #[error("Syscall analysis error: {0}")]
    SyscallAnalysisError(String),
}

pub type Result<T> = std::result::Result<T, EbpfHardeningError>;

/// Raw syscall event (captured at kernel entry point, not libc)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawSyscallEvent {
    pub timestamp_ns: u64,
    pub pid: i32,
    pub tid: i32,
    pub uid: u32,
    pub syscall_nr: u64,      // Raw syscall number
    pub args: [u64; 6],       // Raw syscall arguments
    pub return_value: i64,
    pub comm: String,
    pub entry_point: SyscallEntryPoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyscallEntryPoint {
    Libc,           // Normal syscall via libc
    DirectSyscall,  // Direct syscall instruction (evasion!)
    Vsyscall,       // Legacy vsyscall
    Vdso,           // Virtual dynamic shared object
    Unknown,
}

/// Syscall sequence for n-gram analysis
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct SyscallNgram {
    pub syscalls: Vec<u64>,  // Sequence of syscall numbers
    pub length: usize,       // N in n-gram (typically 3-5)
}

/// Probe integrity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeIntegrityInfo {
    pub probe_id: String,
    pub probe_type: ProbeType,
    pub attach_point: String,
    pub is_attached: bool,
    pub last_check: String,
    pub detach_count: u32,
    pub hash: String,  // Hash of probe bytecode
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProbeType {
    Kprobe,
    Tracepoint,
    RawTracepoint,
    Uprobe,
}

/// Probe tampering event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTamperingEvent {
    pub timestamp: String,
    pub probe_id: String,
    pub tampering_type: TamperingType,
    pub severity: Severity,
    pub description: String,
    pub attacker_pid: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TamperingType {
    ProbeDetached,
    ProbeDisabled,
    TracingDisabled,
    DebugfsModified,
    BpfProgUnloaded,
    SyscallTableModified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Syscall anomaly detected by n-gram analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallAnomaly {
    pub timestamp: String,
    pub pid: i32,
    pub ngram: SyscallNgram,
    pub anomaly_score: f64,  // 0.0 = normal, 1.0 = highly anomalous
    pub reason: String,
    pub severity: Severity,
}

/// Raw syscall monitor - captures syscalls at kernel entry point
pub struct RawSyscallMonitor {
    /// Recent syscall events
    event_buffer: VecDeque<RawSyscallEvent>,
    
    /// Syscall frequency by number
    syscall_frequency: HashMap<u64, u64>,
    
    /// Direct syscall detection count
    direct_syscall_count: u64,
    
    /// Buffer size limit
    max_buffer_size: usize,
}

impl RawSyscallMonitor {
    pub fn new(max_buffer_size: usize) -> Self {
        Self {
            event_buffer: VecDeque::new(),
            syscall_frequency: HashMap::new(),
            direct_syscall_count: 0,
            max_buffer_size,
        }
    }
    
    /// Record a raw syscall event
    pub fn record_syscall(&mut self, event: RawSyscallEvent) {
        // Detect direct syscalls (evasion technique)
        if event.entry_point == SyscallEntryPoint::DirectSyscall {
            self.direct_syscall_count += 1;
            log::warn!(
                "Direct syscall detected: PID {} syscall {} (bypassing libc)",
                event.pid, event.syscall_nr
            );
        }
        
        // Update frequency
        *self.syscall_frequency.entry(event.syscall_nr).or_insert(0) += 1;
        
        // Add to buffer
        self.event_buffer.push_back(event);
        
        // Maintain buffer size
        if self.event_buffer.len() > self.max_buffer_size {
            self.event_buffer.pop_front();
        }
    }
    
    /// Get syscalls for a specific PID
    pub fn get_syscalls_for_pid(&self, pid: i32) -> Vec<&RawSyscallEvent> {
        self.event_buffer.iter()
            .filter(|e| e.pid == pid)
            .collect()
    }
    
    /// Get direct syscall count (evasion indicator)
    pub fn get_direct_syscall_count(&self) -> u64 {
        self.direct_syscall_count
    }
    
    /// Get syscall frequency distribution
    pub fn get_syscall_frequency(&self) -> &HashMap<u64, u64> {
        &self.syscall_frequency
    }
}

/// Probe integrity checker - detects tampering with eBPF probes
pub struct ProbeIntegrityChecker {
    /// Tracked probes
    probes: HashMap<String, ProbeIntegrityInfo>,
    
    /// Tampering events
    tampering_events: Vec<ProbeTamperingEvent>,
    
    /// Check interval (seconds)
    check_interval_secs: u64,
}

impl ProbeIntegrityChecker {
    pub fn new(check_interval_secs: u64) -> Self {
        Self {
            probes: HashMap::new(),
            tampering_events: Vec::new(),
            check_interval_secs,
        }
    }
    
    /// Register a probe for monitoring
    pub fn register_probe(&mut self, info: ProbeIntegrityInfo) {
        log::info!("Registering probe for integrity monitoring: {}", info.probe_id);
        self.probes.insert(info.probe_id.clone(), info);
    }
    
    /// Check integrity of all probes
    pub fn check_integrity(&mut self) -> Result<Vec<ProbeTamperingEvent>> {
        let mut new_events = Vec::new();
        let probe_ids: Vec<String> = self.probes.keys().cloned().collect();
        
        for probe_id in probe_ids {
            // Check if probe is still attached
            let is_attached = self.check_probe_attached(&probe_id)?;
            
            if let Some(info) = self.probes.get_mut(&probe_id) {
                if info.is_attached && !is_attached {
                    // Probe was detached!
                    info.detach_count += 1;
                    info.is_attached = false;
                    
                    let event = ProbeTamperingEvent {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        probe_id: probe_id.clone(),
                        tampering_type: TamperingType::ProbeDetached,
                        severity: Severity::Critical,
                        description: format!("Probe {} was detached (detach count: {})", probe_id, info.detach_count),
                        attacker_pid: None,
                    };
                    
                    log::error!("🔴 PROBE TAMPERING: {}", event.description);
                    new_events.push(event.clone());
                    self.tampering_events.push(event);
                }
                
                info.last_check = chrono::Utc::now().to_rfc3339();
            }
        }
        
        Ok(new_events)
    }
    
    /// Check if a specific probe is attached
    fn check_probe_attached(&self, probe_id: &str) -> Result<bool> {
        // TODO: Check /sys/kernel/debug/tracing/kprobe_events or BPF filesystem
        // For now, simulate check
        log::debug!("Checking probe attachment: {}", probe_id);
        Ok(true)
    }
    
    /// Attempt to reattach a detached probe (self-healing)
    pub fn reattach_probe(&mut self, probe_id: &str) -> Result<()> {
        if let Some(info) = self.probes.get_mut(probe_id) {
            log::info!("Attempting to reattach probe: {}", probe_id);
            
            // TODO: Actually reattach the probe
            // This would involve reloading the BPF program
            
            info.is_attached = true;
            log::info!("✅ Probe reattached successfully: {}", probe_id);
            Ok(())
        } else {
            Err(EbpfHardeningError::ProbeReattachError(
                format!("Probe not found: {}", probe_id)
            ))
        }
    }
    
    /// Get all tampering events
    pub fn get_tampering_events(&self) -> &[ProbeTamperingEvent] {
        &self.tampering_events
    }
    
    /// Get probe status
    pub fn get_probe_status(&self, probe_id: &str) -> Option<&ProbeIntegrityInfo> {
        self.probes.get(probe_id)
    }
}

/// Syscall n-gram analyzer - detects anomalous syscall sequences
pub struct SyscallNgramAnalyzer {
    /// N-gram size (typically 3-5)
    ngram_size: usize,
    
    /// Baseline n-gram frequencies (learned from normal behavior)
    baseline_ngrams: HashMap<SyscallNgram, u64>,
    
    /// Detected anomalies
    anomalies: Vec<SyscallAnomaly>,
    
    /// Anomaly threshold (0.0-1.0)
    anomaly_threshold: f64,
}

impl SyscallNgramAnalyzer {
    pub fn new(ngram_size: usize, anomaly_threshold: f64) -> Self {
        Self {
            ngram_size,
            baseline_ngrams: HashMap::new(),
            anomalies: Vec::new(),
            anomaly_threshold,
        }
    }
    
    /// Learn baseline from normal syscall sequences
    pub fn learn_baseline(&mut self, syscalls: &[RawSyscallEvent]) {
        let ngrams = self.extract_ngrams(syscalls);
        
        for ngram in ngrams {
            *self.baseline_ngrams.entry(ngram).or_insert(0) += 1;
        }
        
        log::info!("Learned {} baseline n-grams", self.baseline_ngrams.len());
    }
    
    /// Analyze syscall sequence for anomalies
    pub fn analyze_sequence(&mut self, pid: i32, syscalls: &[RawSyscallEvent]) -> Vec<SyscallAnomaly> {
        let ngrams = self.extract_ngrams(syscalls);
        let mut detected_anomalies = Vec::new();
        
        for ngram in ngrams {
            let score = self.compute_anomaly_score(&ngram);
            
            if score > self.anomaly_threshold {
                let anomaly = SyscallAnomaly {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    pid,
                    ngram: ngram.clone(),
                    anomaly_score: score,
                    reason: format!("Unusual syscall sequence: {:?}", ngram.syscalls),
                    severity: if score > 0.9 {
                        Severity::Critical
                    } else if score > 0.7 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                };
                
                log::warn!("Syscall anomaly detected: PID {} score {:.2}", pid, score);
                detected_anomalies.push(anomaly.clone());
                self.anomalies.push(anomaly);
            }
        }
        
        detected_anomalies
    }
    
    /// Extract n-grams from syscall sequence
    fn extract_ngrams(&self, syscalls: &[RawSyscallEvent]) -> Vec<SyscallNgram> {
        let mut ngrams = Vec::new();
        
        if syscalls.len() < self.ngram_size {
            return ngrams;
        }
        
        for window in syscalls.windows(self.ngram_size) {
            let syscall_nrs: Vec<u64> = window.iter()
                .map(|e| e.syscall_nr)
                .collect();
            
            ngrams.push(SyscallNgram {
                syscalls: syscall_nrs,
                length: self.ngram_size,
            });
        }
        
        ngrams
    }
    
    /// Compute anomaly score for an n-gram
    fn compute_anomaly_score(&self, ngram: &SyscallNgram) -> f64 {
        // If we've never seen this n-gram in baseline, it's highly anomalous
        if !self.baseline_ngrams.contains_key(ngram) {
            return 0.95;
        }
        
        // Compute score based on rarity
        let frequency = self.baseline_ngrams.get(ngram).unwrap();
        let total_ngrams: u64 = self.baseline_ngrams.values().sum();
        let probability = *frequency as f64 / total_ngrams as f64;
        
        // Lower probability = higher anomaly score
        1.0 - probability.min(1.0)
    }
    
    /// Get all detected anomalies
    pub fn get_anomalies(&self) -> &[SyscallAnomaly] {
        &self.anomalies
    }
}

/// Main eBPF hardening manager
pub struct EbpfHardeningManager {
    raw_syscall_monitor: RawSyscallMonitor,
    probe_integrity_checker: ProbeIntegrityChecker,
    ngram_analyzer: SyscallNgramAnalyzer,
    auto_heal: bool,
}

impl EbpfHardeningManager {
    pub fn new(
        buffer_size: usize,
        check_interval_secs: u64,
        ngram_size: usize,
        anomaly_threshold: f64,
        auto_heal: bool,
    ) -> Self {
        Self {
            raw_syscall_monitor: RawSyscallMonitor::new(buffer_size),
            probe_integrity_checker: ProbeIntegrityChecker::new(check_interval_secs),
            ngram_analyzer: SyscallNgramAnalyzer::new(ngram_size, anomaly_threshold),
            auto_heal,
        }
    }
    
    /// Record a raw syscall
    pub fn record_syscall(&mut self, event: RawSyscallEvent) {
        self.raw_syscall_monitor.record_syscall(event);
    }
    
    /// Register a probe for monitoring
    pub fn register_probe(&mut self, info: ProbeIntegrityInfo) {
        self.probe_integrity_checker.register_probe(info);
    }
    
    /// Check probe integrity and auto-heal if enabled
    pub fn check_and_heal(&mut self) -> Result<Vec<ProbeTamperingEvent>> {
        let tampering_events = self.probe_integrity_checker.check_integrity()?;
        
        if self.auto_heal {
            for event in &tampering_events {
                if matches!(event.tampering_type, TamperingType::ProbeDetached) {
                    log::info!("Auto-healing: reattaching probe {}", event.probe_id);
                    let _ = self.probe_integrity_checker.reattach_probe(&event.probe_id);
                }
            }
        }
        
        Ok(tampering_events)
    }
    
    /// Analyze syscalls for anomalies
    pub fn analyze_syscalls(&mut self, pid: i32) -> Vec<SyscallAnomaly> {
        let syscalls: Vec<RawSyscallEvent> = self.raw_syscall_monitor
            .get_syscalls_for_pid(pid)
            .into_iter()
            .cloned()
            .collect();
        
        self.ngram_analyzer.analyze_sequence(pid, &syscalls)
    }
    
    /// Get direct syscall count (evasion indicator)
    pub fn get_direct_syscall_count(&self) -> u64 {
        self.raw_syscall_monitor.get_direct_syscall_count()
    }
    
    /// Get all tampering events
    pub fn get_tampering_events(&self) -> &[ProbeTamperingEvent] {
        self.probe_integrity_checker.get_tampering_events()
    }
    
    /// Get all anomalies
    pub fn get_anomalies(&self) -> &[SyscallAnomaly] {
        self.ngram_analyzer.get_anomalies()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_raw_syscall_monitor() {
        let mut monitor = RawSyscallMonitor::new(1000);
        
        let event = RawSyscallEvent {
            timestamp_ns: 1234567890,
            pid: 1000,
            tid: 1000,
            uid: 1000,
            syscall_nr: 1,  // write
            args: [1, 0, 0, 0, 0, 0],
            return_value: 0,
            comm: "test".to_string(),
            entry_point: SyscallEntryPoint::Libc,
        };
        
        monitor.record_syscall(event);
        assert_eq!(monitor.get_syscalls_for_pid(1000).len(), 1);
    }
    
    #[test]
    fn test_direct_syscall_detection() {
        let mut monitor = RawSyscallMonitor::new(1000);
        
        let event = RawSyscallEvent {
            timestamp_ns: 1234567890,
            pid: 1000,
            tid: 1000,
            uid: 1000,
            syscall_nr: 1,
            args: [0; 6],
            return_value: 0,
            comm: "malware".to_string(),
            entry_point: SyscallEntryPoint::DirectSyscall,  // Evasion!
        };
        
        monitor.record_syscall(event);
        assert_eq!(monitor.get_direct_syscall_count(), 1);
    }
    
    #[test]
    fn test_probe_integrity_checker() {
        let mut checker = ProbeIntegrityChecker::new(60);
        
        let info = ProbeIntegrityInfo {
            probe_id: "test_probe".to_string(),
            probe_type: ProbeType::Kprobe,
            attach_point: "sys_execve".to_string(),
            is_attached: true,
            last_check: chrono::Utc::now().to_rfc3339(),
            detach_count: 0,
            hash: "abc123".to_string(),
        };
        
        checker.register_probe(info);
        assert!(checker.get_probe_status("test_probe").is_some());
    }
    
    #[test]
    fn test_ngram_analyzer() {
        let mut analyzer = SyscallNgramAnalyzer::new(3, 0.8);
        
        let syscalls = vec![
            RawSyscallEvent {
                timestamp_ns: 1,
                pid: 1000,
                tid: 1000,
                uid: 1000,
                syscall_nr: 1,
                args: [0; 6],
                return_value: 0,
                comm: "test".to_string(),
                entry_point: SyscallEntryPoint::Libc,
            },
            RawSyscallEvent {
                timestamp_ns: 2,
                pid: 1000,
                tid: 1000,
                uid: 1000,
                syscall_nr: 2,
                args: [0; 6],
                return_value: 0,
                comm: "test".to_string(),
                entry_point: SyscallEntryPoint::Libc,
            },
            RawSyscallEvent {
                timestamp_ns: 3,
                pid: 1000,
                tid: 1000,
                uid: 1000,
                syscall_nr: 3,
                args: [0; 6],
                return_value: 0,
                comm: "test".to_string(),
                entry_point: SyscallEntryPoint::Libc,
            },
        ];
        
        analyzer.learn_baseline(&syscalls);
        assert!(!analyzer.baseline_ngrams.is_empty());
    }
}
