use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HardwareMonitorError {
    #[error("CPU performance counter error: {0}")]
    CpuCounterError(String),
    #[error("Memory controller error: {0}")]
    MemoryControllerError(String),
    #[error("PCIe device monitoring error: {0}")]
    PcieError(String),
}

pub type Result<T> = std::result::Result<T, HardwareMonitorError>;

/// Hardware anomaly alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAnomalyAlert {
    pub alert_id: String,
    pub timestamp: String,
    pub anomaly_type: HardwareAnomalyType,
    pub severity: Severity,
    pub description: String,
    pub evidence: HardwareEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardwareAnomalyType {
    CpuCacheAnomaly,
    BranchPredictionAnomaly,
    MemoryTimingAnomaly,
    PcieDeviceAnomaly,
    DmaAnomaly,
    RowhammerDetected,
    SpectreVariant,
    MeltdownVariant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEvidence {
    pub counter_values: HashMap<String, u64>,
    pub baseline_deviation: f64,
    pub affected_cores: Vec<u32>,
    pub memory_addresses: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// CPU performance counter data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuPerformanceCounters {
    pub core_id: u32,
    pub cycles: u64,
    pub instructions: u64,
    pub cache_misses: u64,
    pub cache_references: u64,
    pub branch_misses: u64,
    pub branch_instructions: u64,
    pub page_faults: u64,
    pub context_switches: u64,
}

impl CpuPerformanceCounters {
    /// Calculate IPC (Instructions Per Cycle)
    pub fn ipc(&self) -> f64 {
        if self.cycles == 0 {
            0.0
        } else {
            self.instructions as f64 / self.cycles as f64
        }
    }
    
    /// Calculate cache miss rate
    pub fn cache_miss_rate(&self) -> f64 {
        if self.cache_references == 0 {
            0.0
        } else {
            self.cache_misses as f64 / self.cache_references as f64
        }
    }
    
    /// Calculate branch miss rate
    pub fn branch_miss_rate(&self) -> f64 {
        if self.branch_instructions == 0 {
            0.0
        } else {
            self.branch_misses as f64 / self.branch_instructions as f64
        }
    }
}

/// Memory controller event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryControllerEvent {
    pub timestamp: String,
    pub event_type: MemoryEventType,
    pub address: u64,
    pub value: u64,
    pub channel: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryEventType {
    ReadError,
    WriteError,
    RefreshAnomaly,
    RowhammerAttempt,
    UnexpectedAccess,
}

/// PCIe device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcieDeviceInfo {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u32,
    pub is_authorized: bool,
    pub dma_enabled: bool,
    pub suspicious: bool,
    pub suspicious_reasons: Vec<String>,
}

/// CPU performance monitor
pub struct CpuPerformanceMonitor {
    /// Baseline counters by core
    baselines: HashMap<u32, CpuPerformanceCounters>,
    
    /// Anomaly alerts
    alerts: Vec<HardwareAnomalyAlert>,
    
    /// Anomaly threshold (standard deviations)
    threshold: f64,
}

impl CpuPerformanceMonitor {
    pub fn new(threshold: f64) -> Self {
        Self {
            baselines: HashMap::new(),
            alerts: Vec::new(),
            threshold,
        }
    }
    
    /// Establish baseline
    pub fn establish_baseline(&mut self, core_id: u32, counters: CpuPerformanceCounters) {
        log::info!("Establishing baseline for core {}: IPC={:.2}, cache_miss_rate={:.2}%",
                  core_id, counters.ipc(), counters.cache_miss_rate() * 100.0);
        self.baselines.insert(core_id, counters);
    }
    
    /// Monitor for anomalies
    pub fn monitor_counters(&mut self, counters: CpuPerformanceCounters) -> Option<HardwareAnomalyAlert> {
        if let Some(baseline) = self.baselines.get(&counters.core_id) {
            // Check cache miss rate
            let cache_miss_deviation = (counters.cache_miss_rate() - baseline.cache_miss_rate()).abs() 
                / baseline.cache_miss_rate();
            
            // Check branch miss rate
            let branch_miss_deviation = (counters.branch_miss_rate() - baseline.branch_miss_rate()).abs()
                / baseline.branch_miss_rate();
            
            // Check IPC
            let ipc_deviation = (counters.ipc() - baseline.ipc()).abs() / baseline.ipc();
            
            // Detect Spectre-like attacks (high branch mispredictions)
            if branch_miss_deviation > self.threshold {
                let mut counter_values = HashMap::new();
                counter_values.insert("branch_misses".to_string(), counters.branch_misses);
                counter_values.insert("branch_instructions".to_string(), counters.branch_instructions);
                
                let alert = HardwareAnomalyAlert {
                    alert_id: format!("hw_{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    anomaly_type: HardwareAnomalyType::BranchPredictionAnomaly,
                    severity: Severity::Critical,
                    description: format!("Branch prediction anomaly on core {} (deviation: {:.2}%)",
                                       counters.core_id, branch_miss_deviation * 100.0),
                    evidence: HardwareEvidence {
                        counter_values,
                        baseline_deviation: branch_miss_deviation,
                        affected_cores: vec![counters.core_id],
                        memory_addresses: vec![],
                    },
                };
                
                log::error!("🔴 HARDWARE ANOMALY: Possible Spectre-like attack on core {}",
                           counters.core_id);
                self.alerts.push(alert.clone());
                return Some(alert);
            }
            
            // Detect cache timing attacks (high cache misses)
            if cache_miss_deviation > self.threshold {
                let mut counter_values = HashMap::new();
                counter_values.insert("cache_misses".to_string(), counters.cache_misses);
                counter_values.insert("cache_references".to_string(), counters.cache_references);
                
                let alert = HardwareAnomalyAlert {
                    alert_id: format!("hw_{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    anomaly_type: HardwareAnomalyType::CpuCacheAnomaly,
                    severity: Severity::High,
                    description: format!("Cache timing anomaly on core {} (deviation: {:.2}%)",
                                       counters.core_id, cache_miss_deviation * 100.0),
                    evidence: HardwareEvidence {
                        counter_values,
                        baseline_deviation: cache_miss_deviation,
                        affected_cores: vec![counters.core_id],
                        memory_addresses: vec![],
                    },
                };
                
                log::warn!("🟠 HARDWARE ANOMALY: Possible cache timing attack on core {}",
                          counters.core_id);
                self.alerts.push(alert.clone());
                return Some(alert);
            }
        }
        
        None
    }
    
    /// Get all alerts
    pub fn get_alerts(&self) -> &[HardwareAnomalyAlert] {
        &self.alerts
    }
}

/// Memory controller monitor
pub struct MemoryControllerMonitor {
    /// Memory events
    events: Vec<MemoryControllerEvent>,
    
    /// Rowhammer detection
    row_access_counts: HashMap<u64, u64>,
    
    /// Alerts
    alerts: Vec<HardwareAnomalyAlert>,
    
    /// Rowhammer threshold
    rowhammer_threshold: u64,
}

impl MemoryControllerMonitor {
    pub fn new(rowhammer_threshold: u64) -> Self {
        Self {
            events: Vec::new(),
            row_access_counts: HashMap::new(),
            alerts: Vec::new(),
            rowhammer_threshold,
        }
    }
    
    /// Record memory event
    pub fn record_event(&mut self, event: MemoryControllerEvent) {
        // Track row accesses for Rowhammer detection
        if matches!(event.event_type, MemoryEventType::RowhammerAttempt) {
            let row = event.address >> 12; // Assume 4KB pages
            *self.row_access_counts.entry(row).or_insert(0) += 1;
            
            if let Some(&count) = self.row_access_counts.get(&row) {
                if count > self.rowhammer_threshold {
                    let mut counter_values = HashMap::new();
                    counter_values.insert("row_accesses".to_string(), count);
                    
                    let alert = HardwareAnomalyAlert {
                        alert_id: format!("hw_{}", uuid::Uuid::new_v4()),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        anomaly_type: HardwareAnomalyType::RowhammerDetected,
                        severity: Severity::Critical,
                        description: format!("Rowhammer attack detected on row 0x{:x} ({} accesses)",
                                           row, count),
                        evidence: HardwareEvidence {
                            counter_values,
                            baseline_deviation: 0.0,
                            affected_cores: vec![],
                            memory_addresses: vec![event.address],
                        },
                    };
                    
                    log::error!("🔴 ROWHAMMER DETECTED: Row 0x{:x} accessed {} times", row, count);
                    self.alerts.push(alert);
                }
            }
        }
        
        self.events.push(event);
    }
    
    /// Get all alerts
    pub fn get_alerts(&self) -> &[HardwareAnomalyAlert] {
        &self.alerts
    }
}

/// PCIe device monitor
pub struct PcieDeviceMonitor {
    /// Known devices
    known_devices: HashMap<String, PcieDeviceInfo>,
    
    /// Suspicious devices
    suspicious_devices: Vec<PcieDeviceInfo>,
}

impl PcieDeviceMonitor {
    pub fn new() -> Self {
        Self {
            known_devices: HashMap::new(),
            suspicious_devices: Vec::new(),
        }
    }
    
    /// Register known device
    pub fn register_device(&mut self, device: PcieDeviceInfo) {
        let key = format!("{:02x}:{:02x}.{}", device.bus, device.device, device.function);
        self.known_devices.insert(key, device);
    }
    
    /// Scan for suspicious devices
    pub fn scan_device(&mut self, mut device: PcieDeviceInfo) -> bool {
        let mut suspicious = false;
        let mut reasons = Vec::new();
        
        // Check for unauthorized devices
        let key = format!("{:02x}:{:02x}.{}", device.bus, device.device, device.function);
        if !self.known_devices.contains_key(&key) {
            suspicious = true;
            reasons.push("Unknown device (not in authorized list)".to_string());
        }
        
        // Check for DMA-capable devices
        if device.dma_enabled {
            suspicious = true;
            reasons.push("DMA-capable device (potential DMA attack)".to_string());
        }
        
        // Check for suspicious vendor IDs
        let suspicious_vendors = [0xFFFF, 0x0000];
        if suspicious_vendors.contains(&device.vendor_id) {
            suspicious = true;
            reasons.push(format!("Suspicious vendor ID: 0x{:04x}", device.vendor_id));
        }
        
        if suspicious {
            device.suspicious = true;
            device.suspicious_reasons = reasons;
            log::warn!("Suspicious PCIe device detected: {:02x}:{:02x}.{} (vendor: 0x{:04x})",
                      device.bus, device.device, device.function, device.vendor_id);
            self.suspicious_devices.push(device);
        }
        
        suspicious
    }
    
    /// Get suspicious devices
    pub fn get_suspicious_devices(&self) -> &[PcieDeviceInfo] {
        &self.suspicious_devices
    }
}

impl Default for PcieDeviceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Main hardware monitor
pub struct HardwareMonitor {
    cpu_monitor: CpuPerformanceMonitor,
    memory_monitor: MemoryControllerMonitor,
    pcie_monitor: PcieDeviceMonitor,
}

impl HardwareMonitor {
    pub fn new(cpu_threshold: f64, rowhammer_threshold: u64) -> Self {
        Self {
            cpu_monitor: CpuPerformanceMonitor::new(cpu_threshold),
            memory_monitor: MemoryControllerMonitor::new(rowhammer_threshold),
            pcie_monitor: PcieDeviceMonitor::new(),
        }
    }
    
    /// Get CPU monitor
    pub fn cpu_monitor(&mut self) -> &mut CpuPerformanceMonitor {
        &mut self.cpu_monitor
    }
    
    /// Get memory monitor
    pub fn memory_monitor(&mut self) -> &mut MemoryControllerMonitor {
        &mut self.memory_monitor
    }
    
    /// Get PCIe monitor
    pub fn pcie_monitor(&mut self) -> &mut PcieDeviceMonitor {
        &mut self.pcie_monitor
    }
    
    /// Get comprehensive hardware report
    pub fn get_hardware_report(&self) -> HardwareMonitorReport {
        let mut all_alerts = self.cpu_monitor.get_alerts().to_vec();
        all_alerts.extend(self.memory_monitor.get_alerts().iter().cloned());
        
        HardwareMonitorReport {
            hardware_alerts: all_alerts,
            suspicious_devices: self.pcie_monitor.get_suspicious_devices().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareMonitorReport {
    pub hardware_alerts: Vec<HardwareAnomalyAlert>,
    pub suspicious_devices: Vec<PcieDeviceInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cpu_performance_monitoring() {
        let mut monitor = CpuPerformanceMonitor::new(0.5);
        
        let baseline = CpuPerformanceCounters {
            core_id: 0,
            cycles: 1000000,
            instructions: 800000,
            cache_misses: 1000,
            cache_references: 10000,
            branch_misses: 100,
            branch_instructions: 10000,
            page_faults: 10,
            context_switches: 5,
        };
        
        monitor.establish_baseline(0, baseline);
        
        // Simulate Spectre-like attack (high branch misses)
        let anomalous = CpuPerformanceCounters {
            core_id: 0,
            cycles: 1000000,
            instructions: 800000,
            cache_misses: 1000,
            cache_references: 10000,
            branch_misses: 5000,  // 50x increase!
            branch_instructions: 10000,
            page_faults: 10,
            context_switches: 5,
        };
        
        let alert = monitor.monitor_counters(anomalous);
        assert!(alert.is_some());
    }
    
    #[test]
    fn test_rowhammer_detection() {
        let mut monitor = MemoryControllerMonitor::new(1000);
        
        // Simulate many accesses to same row
        for _ in 0..1500 {
            monitor.record_event(MemoryControllerEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                event_type: MemoryEventType::RowhammerAttempt,
                address: 0x1000,  // Same row
                value: 0,
                channel: 0,
            });
        }
        
        assert!(!monitor.get_alerts().is_empty());
    }
    
    #[test]
    fn test_pcie_device_scanning() {
        let mut monitor = PcieDeviceMonitor::new();
        
        let suspicious_device = PcieDeviceInfo {
            bus: 0,
            device: 1,
            function: 0,
            vendor_id: 0xFFFF,  // Suspicious
            device_id: 0x1234,
            class_code: 0x020000,
            is_authorized: false,
            dma_enabled: true,
            suspicious: false,
            suspicious_reasons: vec![],
        };
        
        let is_suspicious = monitor.scan_device(suspicious_device);
        assert!(is_suspicious);
    }
}
