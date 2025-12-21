use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryForensicsError {
    #[error("Rootkit detected: {0}")]
    RootkitError(String),
    #[error("Memory injection detected: {0}")]
    MemoryInjectionError(String),
    #[error("DKOM detected: {0}")]
    DkomError(String),
    #[error("Kernel module analysis failed: {0}")]
    KernelModuleError(String),
}

pub type Result<T> = std::result::Result<T, MemoryForensicsError>;

/// Rootkit detection alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub rootkit_type: RootkitType,
    pub severity: Severity,
    pub description: String,
    pub evidence: RootkitEvidence,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootkitType {
    UserMode,
    KernelMode,
    Bootkit,
    Hypervisor,
    SyscallHooking,
    VfsHooking,
    IdtHooking,
    SsdtHooking,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitEvidence {
    pub hooked_functions: Vec<String>,
    pub hidden_processes: Vec<i32>,
    pub hidden_files: Vec<String>,
    pub hidden_network_connections: Vec<String>,
    pub kernel_memory_modifications: Vec<MemoryModification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryModification {
    pub address: u64,
    pub size: usize,
    pub original_bytes: Vec<u8>,
    pub modified_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Kernel module information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModuleInfo {
    pub name: String,
    pub size: usize,
    pub load_address: u64,
    pub reference_count: u32,
    pub state: ModuleState,
    pub signature_valid: bool,
    pub hash: String,
    pub suspicious: bool,
    pub suspicious_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleState {
    Live,
    Loading,
    Unloading,
    Unknown,
}

/// Memory injection alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInjectionAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub injection_type: InjectionType,
    pub target_pid: i32,
    pub target_process: String,
    pub injector_pid: Option<i32>,
    pub injected_address: u64,
    pub injected_size: usize,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionType {
    CodeInjection,
    DllInjection,
    ProcessHollowing,
    AtomBombing,
    ReflectiveLoading,
    ThreadHijacking,
}

/// DKOM (Direct Kernel Object Manipulation) alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkomAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub dkom_type: DkomType,
    pub affected_object: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: DkomEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DkomType {
    ProcessHiding,
    ThreadHiding,
    DriverHiding,
    PortHiding,
    FileHiding,
    RegistryHiding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkomEvidence {
    pub object_address: u64,
    pub list_manipulation: bool,
    pub structure_modification: Vec<String>,
    pub hidden_from: Vec<String>,  // e.g., "PsActiveProcessHead", "EPROCESS list"
}

/// Rootkit detector
pub struct RootkitDetector {
    /// Known good syscall addresses
    syscall_baseline: HashMap<String, u64>,
    
    /// Detected rootkits
    alerts: Vec<RootkitAlert>,
}

impl RootkitDetector {
    pub fn new() -> Self {
        Self {
            syscall_baseline: HashMap::new(),
            alerts: Vec::new(),
        }
    }
    
    /// Establish baseline for syscall addresses
    pub fn establish_baseline(&mut self, syscall_name: String, address: u64) {
        self.syscall_baseline.insert(syscall_name, address);
    }
    
    /// Check for syscall hooking
    pub fn check_syscall_hooks(&mut self, syscall_name: &str, current_address: u64) -> Option<RootkitAlert> {
        if let Some(&baseline_address) = self.syscall_baseline.get(syscall_name) {
            if baseline_address != current_address {
                let alert = RootkitAlert {
                    alert_id: format!("rootkit_{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    rootkit_type: RootkitType::SyscallHooking,
                    severity: Severity::Critical,
                    description: format!("Syscall hook detected: {} (baseline: 0x{:x}, current: 0x{:x})",
                                       syscall_name, baseline_address, current_address),
                    evidence: RootkitEvidence {
                        hooked_functions: vec![syscall_name.to_string()],
                        hidden_processes: vec![],
                        hidden_files: vec![],
                        hidden_network_connections: vec![],
                        kernel_memory_modifications: vec![MemoryModification {
                            address: baseline_address,
                            size: 8,
                            original_bytes: baseline_address.to_le_bytes().to_vec(),
                            modified_bytes: current_address.to_le_bytes().to_vec(),
                        }],
                    },
                    recommended_action: "System compromised - immediate forensic analysis required".to_string(),
                };
                
                log::error!("🔴 ROOTKIT DETECTED: Syscall hook on {}", syscall_name);
                self.alerts.push(alert.clone());
                return Some(alert);
            }
        }
        None
    }
    
    /// Detect hidden processes
    pub fn detect_hidden_processes(&mut self, visible_pids: &[i32], all_pids: &[i32]) -> Option<RootkitAlert> {
        let visible_set: HashSet<_> = visible_pids.iter().collect();
        let hidden_pids: Vec<i32> = all_pids.iter()
            .filter(|pid| !visible_set.contains(pid))
            .copied()
            .collect();
        
        if !hidden_pids.is_empty() {
            let alert = RootkitAlert {
                alert_id: format!("rootkit_{}", uuid::Uuid::new_v4()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                rootkit_type: RootkitType::KernelMode,
                severity: Severity::Critical,
                description: format!("Hidden processes detected: {} processes hidden from userspace",
                                   hidden_pids.len()),
                evidence: RootkitEvidence {
                    hooked_functions: vec![],
                    hidden_processes: hidden_pids.clone(),
                    hidden_files: vec![],
                    hidden_network_connections: vec![],
                    kernel_memory_modifications: vec![],
                },
                recommended_action: "Kernel-mode rootkit detected - system reboot from clean media required".to_string(),
            };
            
            log::error!("🔴 ROOTKIT DETECTED: {} hidden processes", hidden_pids.len());
            self.alerts.push(alert.clone());
            return Some(alert);
        }
        
        None
    }
    
    /// Get all alerts
    pub fn get_alerts(&self) -> &[RootkitAlert] {
        &self.alerts
    }
}

impl Default for RootkitDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Kernel module analyzer
pub struct KernelModuleAnalyzer {
    /// Known good module hashes
    trusted_modules: HashMap<String, String>,
    
    /// Suspicious modules
    suspicious_modules: Vec<KernelModuleInfo>,
}

impl KernelModuleAnalyzer {
    pub fn new() -> Self {
        Self {
            trusted_modules: HashMap::new(),
            suspicious_modules: Vec::new(),
        }
    }
    
    /// Register a trusted kernel module
    pub fn register_trusted_module(&mut self, name: String, hash: String) {
        self.trusted_modules.insert(name, hash);
    }
    
    /// Analyze a kernel module
    pub fn analyze_module(&mut self, mut module: KernelModuleInfo) -> bool {
        let mut suspicious = false;
        let mut reasons = Vec::new();
        
        // Check signature
        if !module.signature_valid {
            suspicious = true;
            reasons.push("Invalid or missing signature".to_string());
        }
        
        // Check against trusted list
        if let Some(trusted_hash) = self.trusted_modules.get(&module.name) {
            if trusted_hash != &module.hash {
                suspicious = true;
                reasons.push(format!("Hash mismatch (expected: {}, actual: {})",
                                   trusted_hash, module.hash));
            }
        } else {
            // Unknown module
            suspicious = true;
            reasons.push("Unknown module (not in trusted list)".to_string());
        }
        
        // Check for suspicious names
        let suspicious_patterns = ["rootkit", "hide", "hook", "stealth", "backdoor"];
        for pattern in &suspicious_patterns {
            if module.name.to_lowercase().contains(pattern) {
                suspicious = true;
                reasons.push(format!("Suspicious name pattern: {}", pattern));
            }
        }
        
        // Check for unusual load addresses
        if module.load_address < 0xffffffff80000000 {
            suspicious = true;
            reasons.push("Unusual load address (outside kernel space)".to_string());
        }
        
        if suspicious {
            module.suspicious = true;
            module.suspicious_reasons = reasons;
            log::warn!("Suspicious kernel module detected: {}", module.name);
            self.suspicious_modules.push(module);
        }
        
        suspicious
    }
    
    /// Get suspicious modules
    pub fn get_suspicious_modules(&self) -> &[KernelModuleInfo] {
        &self.suspicious_modules
    }
}

impl Default for KernelModuleAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory injection detector
pub struct MemoryInjectionDetector {
    /// Tracked processes
    process_memory: HashMap<i32, Vec<MemoryRegion>>,
    
    /// Injection alerts
    alerts: Vec<MemoryInjectionAlert>,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start_address: u64,
    pub size: usize,
    pub permissions: String,
    pub is_executable: bool,
}

impl MemoryInjectionDetector {
    pub fn new() -> Self {
        Self {
            process_memory: HashMap::new(),
            alerts: Vec::new(),
        }
    }
    
    /// Track process memory regions
    pub fn track_memory_region(&mut self, pid: i32, region: MemoryRegion) {
        self.process_memory.entry(pid).or_insert_with(Vec::new).push(region);
    }
    
    /// Detect memory injection
    pub fn detect_injection(
        &mut self,
        target_pid: i32,
        target_process: String,
        injected_address: u64,
        injected_size: usize,
        injector_pid: Option<i32>,
    ) -> MemoryInjectionAlert {
        let alert = MemoryInjectionAlert {
            alert_id: format!("injection_{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            injection_type: InjectionType::CodeInjection,
            target_pid,
            target_process: target_process.clone(),
            injector_pid,
            injected_address,
            injected_size,
            severity: Severity::Critical,
            description: format!("Memory injection detected in process {} (PID: {})",
                               target_process, target_pid),
        };
        
        log::error!("🔴 MEMORY INJECTION: {} bytes at 0x{:x} in PID {}",
                   injected_size, injected_address, target_pid);
        self.alerts.push(alert.clone());
        alert
    }
    
    /// Get all alerts
    pub fn get_alerts(&self) -> &[MemoryInjectionAlert] {
        &self.alerts
    }
}

impl Default for MemoryInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// DKOM (Direct Kernel Object Manipulation) detector
pub struct DkomDetector {
    /// Known kernel object addresses
    kernel_objects: HashMap<String, u64>,
    
    /// DKOM alerts
    alerts: Vec<DkomAlert>,
}

impl DkomDetector {
    pub fn new() -> Self {
        Self {
            kernel_objects: HashMap::new(),
            alerts: Vec::new(),
        }
    }
    
    /// Register a kernel object
    pub fn register_kernel_object(&mut self, name: String, address: u64) {
        self.kernel_objects.insert(name, address);
    }
    
    /// Detect DKOM - process hiding
    pub fn detect_process_hiding(
        &mut self,
        process_name: &str,
        expected_in_list: bool,
        actually_in_list: bool,
    ) -> Option<DkomAlert> {
        if expected_in_list != actually_in_list {
            let alert = DkomAlert {
                alert_id: format!("dkom_{}", uuid::Uuid::new_v4()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                dkom_type: DkomType::ProcessHiding,
                affected_object: process_name.to_string(),
                severity: Severity::Critical,
                description: format!("DKOM detected: Process {} hidden via list manipulation",
                                   process_name),
                evidence: DkomEvidence {
                    object_address: 0,  // Would be filled with actual EPROCESS address
                    list_manipulation: true,
                    structure_modification: vec!["ActiveProcessLinks".to_string()],
                    hidden_from: vec!["PsActiveProcessHead".to_string()],
                },
            };
            
            log::error!("🔴 DKOM DETECTED: Process hiding via list manipulation");
            self.alerts.push(alert.clone());
            return Some(alert);
        }
        
        None
    }
    
    /// Get all alerts
    pub fn get_alerts(&self) -> &[DkomAlert] {
        &self.alerts
    }
}

impl Default for DkomDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Main memory forensics manager
pub struct MemoryForensicsManager {
    rootkit_detector: RootkitDetector,
    kernel_module_analyzer: KernelModuleAnalyzer,
    memory_injection_detector: MemoryInjectionDetector,
    dkom_detector: DkomDetector,
}

impl MemoryForensicsManager {
    pub fn new() -> Self {
        Self {
            rootkit_detector: RootkitDetector::new(),
            kernel_module_analyzer: KernelModuleAnalyzer::new(),
            memory_injection_detector: MemoryInjectionDetector::new(),
            dkom_detector: DkomDetector::new(),
        }
    }
    
    /// Get rootkit detector
    pub fn rootkit_detector(&mut self) -> &mut RootkitDetector {
        &mut self.rootkit_detector
    }
    
    /// Get kernel module analyzer
    pub fn kernel_module_analyzer(&mut self) -> &mut KernelModuleAnalyzer {
        &mut self.kernel_module_analyzer
    }
    
    /// Get memory injection detector
    pub fn memory_injection_detector(&mut self) -> &mut MemoryInjectionDetector {
        &mut self.memory_injection_detector
    }
    
    /// Get DKOM detector
    pub fn dkom_detector(&mut self) -> &mut DkomDetector {
        &mut self.dkom_detector
    }
    
    /// Get comprehensive forensics report
    pub fn get_forensics_report(&self) -> MemoryForensicsReport {
        MemoryForensicsReport {
            rootkit_alerts: self.rootkit_detector.get_alerts().to_vec(),
            suspicious_modules: self.kernel_module_analyzer.get_suspicious_modules().to_vec(),
            injection_alerts: self.memory_injection_detector.get_alerts().to_vec(),
            dkom_alerts: self.dkom_detector.get_alerts().to_vec(),
        }
    }
}

impl Default for MemoryForensicsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryForensicsReport {
    pub rootkit_alerts: Vec<RootkitAlert>,
    pub suspicious_modules: Vec<KernelModuleInfo>,
    pub injection_alerts: Vec<MemoryInjectionAlert>,
    pub dkom_alerts: Vec<DkomAlert>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_syscall_hook_detection() {
        let mut detector = RootkitDetector::new();
        
        detector.establish_baseline("sys_read".to_string(), 0xffffffff81000000);
        
        let alert = detector.check_syscall_hooks("sys_read", 0xffffffff82000000);
        assert!(alert.is_some());
    }
    
    #[test]
    fn test_hidden_process_detection() {
        let mut detector = RootkitDetector::new();
        
        let visible_pids = vec![1, 2, 3];
        let all_pids = vec![1, 2, 3, 666, 1337];  // 666 and 1337 are hidden
        
        let alert = detector.detect_hidden_processes(&visible_pids, &all_pids);
        assert!(alert.is_some());
    }
    
    #[test]
    fn test_kernel_module_analysis() {
        let mut analyzer = KernelModuleAnalyzer::new();
        
        analyzer.register_trusted_module("legitimate".to_string(), "abc123".to_string());
        
        let suspicious_module = KernelModuleInfo {
            name: "rootkit_module".to_string(),
            size: 4096,
            load_address: 0xffffffff81000000,
            reference_count: 0,
            state: ModuleState::Live,
            signature_valid: false,
            hash: "malicious".to_string(),
            suspicious: false,
            suspicious_reasons: vec![],
        };
        
        let is_suspicious = analyzer.analyze_module(suspicious_module);
        assert!(is_suspicious);
    }
    
    #[test]
    fn test_memory_injection_detection() {
        let mut detector = MemoryInjectionDetector::new();
        
        let alert = detector.detect_injection(
            1337,
            "victim".to_string(),
            0x7fff00000000,
            4096,
            Some(666),
        );
        
        assert_eq!(alert.target_pid, 1337);
        assert_eq!(alert.injector_pid, Some(666));
    }
    
    #[test]
    fn test_dkom_detection() {
        let mut detector = DkomDetector::new();
        
        let alert = detector.detect_process_hiding("malware", true, false);
        assert!(alert.is_some());
    }
}
