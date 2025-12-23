use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;

pub mod ebpf_hooks;

#[derive(Debug, Error)]
pub enum FilelessDetectorError {
    #[error("Failed to monitor memfd: {0}")]
    MemfdMonitorError(String),
    #[error("Failed to detect process injection: {0}")]
    InjectionDetectionError(String),
    #[error("Failed to monitor /dev/shm: {0}")]
    ShmMonitorError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, FilelessDetectorError>;

/// Information about an anonymous file descriptor created via memfd_create
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemfdInfo {
    pub pid: i32,
    pub fd: i32,
    pub name: String,
    pub size: u64,
    pub created_at: String,
    pub flags: u32,
    pub executed: bool,
}

/// Information about a process injection attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInjectionEvent {
    pub timestamp: String,
    pub injector_pid: i32,
    pub target_pid: i32,
    pub injection_type: InjectionType,
    pub memory_address: Option<u64>,
    pub bytes_written: usize,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionType {
    PtracePokeText,  // PTRACE_POKETEXT
    PtraceSetRegs,   // PTRACE_SETREGS
    ProcessVmWritev, // process_vm_writev syscall
    ProcMemWrite,    // Write to /proc/[pid]/mem
    LdPreload,       // LD_PRELOAD hijacking
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Information about execution from /dev/shm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShmExecutionEvent {
    pub timestamp: String,
    pub pid: i32,
    pub file_path: PathBuf,
    pub file_hash: String,
    pub file_size: u64,
    pub executed: bool,
}

/// Alert generated when fileless malware is detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilelessAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub alert_type: FilelessAlertType,
    pub severity: Severity,
    pub description: String,
    pub evidence: FilelessEvidence,
    pub recommended_action: String,
}

/// Evasion statistics from hardening manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionStats {
    pub direct_syscall_count: u64,
    pub probe_tampering_count: u64,
    pub syscall_anomaly_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilelessAlertType {
    MemfdExecution,
    ProcessInjection,
    ShmExecution,
    SuspiciousMemoryActivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilelessEvidence {
    Memfd(MemfdInfo),
    Injection(ProcessInjectionEvent),
    Shm(ShmExecutionEvent),
}

/// Main fileless malware detector
pub struct FilelessDetector {
    /// Track memfd file descriptors by PID
    memfd_tracker: HashMap<i32, Vec<MemfdInfo>>,

    /// Track process injection events
    injection_monitor: ProcessInjectionMonitor,

    /// Track /dev/shm executions
    shm_monitor: ShmExecutionMonitor,

    /// Alert history
    alerts: Vec<FilelessAlert>,

    /// eBPF hook manager (optional - requires root)
    ebpf_manager: Option<ebpf_hooks::FilelessEbpfManager>,

    /// eBPF hardening manager (evasion detection)
    hardening_manager: Option<ebpf_hardening::EbpfHardeningManager>,
}

impl FilelessDetector {
    pub fn new() -> Self {
        Self {
            memfd_tracker: HashMap::new(),
            injection_monitor: ProcessInjectionMonitor::new(),
            shm_monitor: ShmExecutionMonitor::new(),
            alerts: Vec::new(),
            ebpf_manager: None,
            hardening_manager: None,
        }
    }

    /// Create detector with eBPF hooks enabled (requires root)
    pub fn new_with_ebpf(config: ebpf_hooks::EbpfHookConfig) -> Result<Self> {
        let mut ebpf_manager = ebpf_hooks::FilelessEbpfManager::new(config);
        ebpf_manager.initialize().map_err(|e| {
            FilelessDetectorError::MemfdMonitorError(format!("eBPF init failed: {e}"))
        })?;

        Ok(Self {
            memfd_tracker: HashMap::new(),
            injection_monitor: ProcessInjectionMonitor::new(),
            shm_monitor: ShmExecutionMonitor::new(),
            alerts: Vec::new(),
            ebpf_manager: Some(ebpf_manager),
            hardening_manager: None,
        })
    }

    /// Create detector with eBPF hooks AND hardening (full protection)
    pub fn new_with_hardening(
        hook_config: ebpf_hooks::EbpfHookConfig,
        enable_hardening: bool,
    ) -> Result<Self> {
        let mut ebpf_manager = ebpf_hooks::FilelessEbpfManager::new(hook_config);
        ebpf_manager.initialize().map_err(|e| {
            FilelessDetectorError::MemfdMonitorError(format!("eBPF init failed: {e}"))
        })?;

        let hardening_manager = if enable_hardening {
            Some(ebpf_hardening::EbpfHardeningManager::new(
                10000, // buffer_size
                60,    // check_interval_secs
                3,     // ngram_size
                0.8,   // anomaly_threshold
                true,  // auto_heal
            ))
        } else {
            None
        };

        Ok(Self {
            memfd_tracker: HashMap::new(),
            injection_monitor: ProcessInjectionMonitor::new(),
            shm_monitor: ShmExecutionMonitor::new(),
            alerts: Vec::new(),
            ebpf_manager: Some(ebpf_manager),
            hardening_manager,
        })
    }

    /// Get evasion statistics
    pub fn get_evasion_stats(&self) -> Option<EvasionStats> {
        self.hardening_manager.as_ref().map(|hm| EvasionStats {
            direct_syscall_count: hm.get_direct_syscall_count(),
            probe_tampering_count: hm.get_tampering_events().len() as u64,
            syscall_anomaly_count: hm.get_anomalies().len() as u64,
        })
    }

    /// Process eBPF events and generate alerts
    pub fn process_ebpf_events(&mut self) -> Result<Vec<FilelessAlert>> {
        let mut new_alerts = Vec::new();

        if let Some(ref mut manager) = self.ebpf_manager {
            let events = manager.poll_events();

            for event in events {
                match event {
                    ebpf_hooks::FilelessEbpfEvent::MemfdCreate(e) => {
                        self.track_memfd_create(e.pid, e.fd, e.name.clone(), e.flags)?;
                    }
                    ebpf_hooks::FilelessEbpfEvent::MemfdExec(e) => {
                        if let Some(alert) = self.track_memfd_execution(e.pid, e.fd)? {
                            new_alerts.push(alert);
                        }
                    }
                    ebpf_hooks::FilelessEbpfEvent::Ptrace(e) => {
                        let injection_type = match e.request {
                            1 => InjectionType::PtracePokeText, // PTRACE_POKETEXT
                            13 => InjectionType::PtraceSetRegs, // PTRACE_SETREGS
                            _ => InjectionType::Unknown,
                        };
                        if let Some(alert) = self.detect_process_injection(
                            e.pid,
                            e.target_pid,
                            injection_type,
                            Some(e.addr),
                            8, // ptrace writes 8 bytes at a time
                        )? {
                            new_alerts.push(alert);
                        }
                    }
                    ebpf_hooks::FilelessEbpfEvent::ProcessVmWritev(e) => {
                        if let Some(alert) = self.detect_process_injection(
                            e.pid,
                            e.target_pid,
                            InjectionType::ProcessVmWritev,
                            None,
                            e.bytes_written,
                        )? {
                            new_alerts.push(alert);
                        }
                    }
                    ebpf_hooks::FilelessEbpfEvent::ProcMemWrite(e) => {
                        if let Some(alert) = self.detect_process_injection(
                            e.pid,
                            e.target_pid,
                            InjectionType::ProcMemWrite,
                            Some(e.offset),
                            e.bytes_written,
                        )? {
                            new_alerts.push(alert);
                        }
                    }
                    ebpf_hooks::FilelessEbpfEvent::ShmExec(e) => {
                        if let Some(alert) = self.track_shm_execution(e.pid, e.path.into())? {
                            new_alerts.push(alert);
                        }
                    }
                }
            }
        }

        Ok(new_alerts)
    }

    /// Track a memfd_create syscall
    pub fn track_memfd_create(
        &mut self,
        pid: i32,
        fd: i32,
        name: String,
        flags: u32,
    ) -> Result<()> {
        let info = MemfdInfo {
            pid,
            fd,
            name: name.clone(),
            size: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            flags,
            executed: false,
        };

        self.memfd_tracker
            .entry(pid)
            .or_default()
            .push(info.clone());

        log::info!("Tracked memfd_create: pid={pid}, fd={fd}, name={name}");

        Ok(())
    }

    /// Track memfd execution (when execve is called on memfd)
    pub fn track_memfd_execution(&mut self, pid: i32, fd: i32) -> Result<Option<FilelessAlert>> {
        if let Some(memfds) = self.memfd_tracker.get_mut(&pid) {
            if let Some(memfd) = memfds.iter_mut().find(|m| m.fd == fd) {
                memfd.executed = true;

                let alert = FilelessAlert {
                    alert_id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    alert_type: FilelessAlertType::MemfdExecution,
                    severity: Severity::Critical,
                    description: format!(
                        "In-memory execution detected: PID {} executed memfd '{}' (fd={})",
                        pid, memfd.name, fd
                    ),
                    evidence: FilelessEvidence::Memfd(memfd.clone()),
                    recommended_action: "Investigate process lineage, capture memory dump, check for C2 communication".to_string(),
                };

                log::warn!("FILELESS EXECUTION DETECTED: {}", alert.description);
                self.alerts.push(alert.clone());

                return Ok(Some(alert));
            }
        }

        Ok(None)
    }

    /// Detect process injection
    pub fn detect_process_injection(
        &mut self,
        injector_pid: i32,
        target_pid: i32,
        injection_type: InjectionType,
        memory_address: Option<u64>,
        bytes_written: usize,
    ) -> Result<Option<FilelessAlert>> {
        let event = ProcessInjectionEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            injector_pid,
            target_pid,
            injection_type: injection_type.clone(),
            memory_address,
            bytes_written,
            severity: Severity::Critical,
        };

        self.injection_monitor.record_injection(event.clone());

        let alert = FilelessAlert {
            alert_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            alert_type: FilelessAlertType::ProcessInjection,
            severity: Severity::Critical,
            description: format!(
                "Process injection detected: PID {injector_pid} injected into PID {target_pid} using {injection_type:?}"
            ),
            evidence: FilelessEvidence::Injection(event),
            recommended_action:
                "Terminate injector process, capture memory dump of target, analyze injected code"
                    .to_string(),
        };

        log::warn!("PROCESS INJECTION DETECTED: {}", alert.description);
        self.alerts.push(alert.clone());

        Ok(Some(alert))
    }

    /// Track /dev/shm execution
    pub fn track_shm_execution(
        &mut self,
        pid: i32,
        file_path: PathBuf,
    ) -> Result<Option<FilelessAlert>> {
        let event = ShmExecutionEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            pid,
            file_path: file_path.clone(),
            file_hash: self.compute_file_hash(&file_path)?,
            file_size: std::fs::metadata(&file_path)?.len(),
            executed: true,
        };

        self.shm_monitor.record_execution(event.clone());

        let alert = FilelessAlert {
            alert_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            alert_type: FilelessAlertType::ShmExecution,
            severity: Severity::High,
            description: format!(
                "Shared memory execution detected: PID {} executed {}",
                pid,
                file_path.display()
            ),
            evidence: FilelessEvidence::Shm(event),
            recommended_action:
                "Capture file from /dev/shm, analyze for malware, check process lineage".to_string(),
        };

        log::warn!("SHM EXECUTION DETECTED: {}", alert.description);
        self.alerts.push(alert.clone());

        Ok(Some(alert))
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[FilelessAlert] {
        &self.alerts
    }

    /// Get alerts by severity
    pub fn get_alerts_by_severity(&self, severity: Severity) -> Vec<FilelessAlert> {
        self.alerts.iter()
            .filter(|a| matches!(a.severity, ref s if std::mem::discriminant(s) == std::mem::discriminant(&severity)))
            .cloned()
            .collect()
    }

    /// Clear old alerts (older than specified hours)
    pub fn clear_old_alerts(&mut self, hours: i64) {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(hours);
        self.alerts.retain(|alert| {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&alert.timestamp) {
                ts.with_timezone(&chrono::Utc) > cutoff
            } else {
                true
            }
        });
    }

    fn compute_file_hash(&self, path: &PathBuf) -> Result<String> {
        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            use sha2::Digest;
            hasher.update(&buffer[..n]);
        }

        use sha2::Digest;
        Ok(format!("{:x}", hasher.finalize()))
    }
}

impl Default for FilelessDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Monitor for process injection events
pub struct ProcessInjectionMonitor {
    injection_events: Vec<ProcessInjectionEvent>,
}

impl ProcessInjectionMonitor {
    pub fn new() -> Self {
        Self {
            injection_events: Vec::new(),
        }
    }

    pub fn record_injection(&mut self, event: ProcessInjectionEvent) {
        self.injection_events.push(event);
    }

    pub fn get_injections_by_pid(&self, pid: i32) -> Vec<&ProcessInjectionEvent> {
        self.injection_events
            .iter()
            .filter(|e| e.injector_pid == pid || e.target_pid == pid)
            .collect()
    }
}

impl Default for ProcessInjectionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Monitor for /dev/shm executions
pub struct ShmExecutionMonitor {
    executions: Vec<ShmExecutionEvent>,
}

impl ShmExecutionMonitor {
    pub fn new() -> Self {
        Self {
            executions: Vec::new(),
        }
    }

    pub fn record_execution(&mut self, event: ShmExecutionEvent) {
        self.executions.push(event);
    }

    pub fn get_executions_by_pid(&self, pid: i32) -> Vec<&ShmExecutionEvent> {
        self.executions.iter().filter(|e| e.pid == pid).collect()
    }
}

impl Default for ShmExecutionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memfd_tracking() {
        let mut detector = FilelessDetector::new();

        detector
            .track_memfd_create(1000, 3, "malware".to_string(), 0)
            .unwrap();

        assert_eq!(detector.memfd_tracker.len(), 1);
        assert_eq!(detector.memfd_tracker.get(&1000).unwrap().len(), 1);
    }

    #[test]
    fn test_memfd_execution_alert() {
        let mut detector = FilelessDetector::new();

        detector
            .track_memfd_create(1000, 3, "malware".to_string(), 0)
            .unwrap();
        let alert = detector.track_memfd_execution(1000, 3).unwrap();

        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert!(matches!(
            alert.alert_type,
            FilelessAlertType::MemfdExecution
        ));
        assert!(matches!(alert.severity, Severity::Critical));
    }

    #[test]
    fn test_process_injection_detection() {
        let mut detector = FilelessDetector::new();

        let alert = detector
            .detect_process_injection(
                1000,
                2000,
                InjectionType::PtracePokeText,
                Some(0x7fff0000),
                4096,
            )
            .unwrap();

        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert!(matches!(
            alert.alert_type,
            FilelessAlertType::ProcessInjection
        ));
        assert!(matches!(alert.severity, Severity::Critical));
    }
}
