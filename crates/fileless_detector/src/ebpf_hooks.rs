use serde::{Deserialize, Serialize};

/// eBPF event for memfd_create syscall
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemfdCreateEvent {
    pub timestamp_ns: u64,
    pub pid: i32,
    pub tid: i32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,  // Process name
    pub fd: i32,       // File descriptor returned
    pub name: String,  // Name passed to memfd_create
    pub flags: u32,    // MFD_CLOEXEC, MFD_ALLOW_SEALING, etc.
}

/// eBPF event for ptrace syscall
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtraceEvent {
    pub timestamp_ns: u64,
    pub pid: i32,           // Tracer PID
    pub tid: i32,
    pub uid: u32,
    pub target_pid: i32,    // Tracee PID
    pub request: i64,       // PTRACE_POKETEXT, PTRACE_SETREGS, etc.
    pub addr: u64,          // Memory address
    pub data: u64,          // Data being written
    pub comm: String,
}

/// eBPF event for process_vm_writev syscall
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessVmWritevEvent {
    pub timestamp_ns: u64,
    pub pid: i32,
    pub target_pid: i32,
    pub local_iov_count: usize,
    pub remote_iov_count: usize,
    pub bytes_written: usize,
    pub comm: String,
}

/// eBPF event for /proc/[pid]/mem writes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcMemWriteEvent {
    pub timestamp_ns: u64,
    pub pid: i32,
    pub target_pid: i32,  // Extracted from path
    pub path: String,     // /proc/[pid]/mem
    pub offset: u64,
    pub bytes_written: usize,
    pub comm: String,
}

/// eBPF event for /dev/shm file execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShmExecEvent {
    pub timestamp_ns: u64,
    pub pid: i32,
    pub uid: u32,
    pub path: String,     // /dev/shm/...
    pub argv: Vec<String>,
    pub comm: String,
}

/// eBPF event for execve on memfd
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemfdExecEvent {
    pub timestamp_ns: u64,
    pub pid: i32,
    pub uid: u32,
    pub fd: i32,
    pub fd_path: String,  // /proc/self/fd/N
    pub argv: Vec<String>,
    pub comm: String,
}

/// Unified fileless event from eBPF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilelessEbpfEvent {
    MemfdCreate(MemfdCreateEvent),
    MemfdExec(MemfdExecEvent),
    Ptrace(PtraceEvent),
    ProcessVmWritev(ProcessVmWritevEvent),
    ProcMemWrite(ProcMemWriteEvent),
    ShmExec(ShmExecEvent),
}

impl FilelessEbpfEvent {
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            Self::MemfdCreate(e) => e.timestamp_ns,
            Self::MemfdExec(e) => e.timestamp_ns,
            Self::Ptrace(e) => e.timestamp_ns,
            Self::ProcessVmWritev(e) => e.timestamp_ns,
            Self::ProcMemWrite(e) => e.timestamp_ns,
            Self::ShmExec(e) => e.timestamp_ns,
        }
    }
    
    pub fn pid(&self) -> i32 {
        match self {
            Self::MemfdCreate(e) => e.pid,
            Self::MemfdExec(e) => e.pid,
            Self::Ptrace(e) => e.pid,
            Self::ProcessVmWritev(e) => e.pid,
            Self::ProcMemWrite(e) => e.pid,
            Self::ShmExec(e) => e.pid,
        }
    }
    
    pub fn event_type(&self) -> &str {
        match self {
            Self::MemfdCreate(_) => "memfd_create",
            Self::MemfdExec(_) => "memfd_exec",
            Self::Ptrace(_) => "ptrace",
            Self::ProcessVmWritev(_) => "process_vm_writev",
            Self::ProcMemWrite(_) => "proc_mem_write",
            Self::ShmExec(_) => "shm_exec",
        }
    }
}

/// eBPF hook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfHookConfig {
    pub enable_memfd_create: bool,
    pub enable_ptrace: bool,
    pub enable_process_vm_writev: bool,
    pub enable_proc_mem_write: bool,
    pub enable_shm_exec: bool,
    pub buffer_size: usize,
    pub sample_rate: u32,  // 1 = capture all, 10 = capture 1/10
}

impl Default for EbpfHookConfig {
    fn default() -> Self {
        Self {
            enable_memfd_create: true,
            enable_ptrace: true,
            enable_process_vm_writev: true,
            enable_proc_mem_write: true,
            enable_shm_exec: true,
            buffer_size: 8192,
            sample_rate: 1,  // Capture everything for fileless detection
        }
    }
}

/// eBPF program manager for fileless detection
pub struct FilelessEbpfManager {
    config: EbpfHookConfig,
    event_buffer: Vec<FilelessEbpfEvent>,
}

impl FilelessEbpfManager {
    pub fn new(config: EbpfHookConfig) -> Self {
        Self {
            config,
            event_buffer: Vec::new(),
        }
    }
    
    /// Initialize eBPF programs
    pub fn initialize(&mut self) -> Result<(), String> {
        log::info!("Initializing fileless detection eBPF hooks...");
        
        if self.config.enable_memfd_create {
            self.attach_memfd_create_hook()?;
        }
        
        if self.config.enable_ptrace {
            self.attach_ptrace_hook()?;
        }
        
        if self.config.enable_process_vm_writev {
            self.attach_process_vm_writev_hook()?;
        }
        
        if self.config.enable_proc_mem_write {
            self.attach_proc_mem_write_hook()?;
        }
        
        if self.config.enable_shm_exec {
            self.attach_shm_exec_hook()?;
        }
        
        log::info!("Fileless detection eBPF hooks initialized successfully");
        Ok(())
    }
    
    /// Attach memfd_create syscall hook
    fn attach_memfd_create_hook(&self) -> Result<(), String> {
        log::info!("Attaching memfd_create hook (syscall 319)");
        // TODO: Load and attach eBPF program
        // This would use libbpf-rs or aya to load the BPF program
        Ok(())
    }
    
    /// Attach ptrace syscall hook
    fn attach_ptrace_hook(&self) -> Result<(), String> {
        log::info!("Attaching ptrace hook (syscall 101)");
        // TODO: Load and attach eBPF program
        Ok(())
    }
    
    /// Attach process_vm_writev syscall hook
    fn attach_process_vm_writev_hook(&self) -> Result<(), String> {
        log::info!("Attaching process_vm_writev hook (syscall 311)");
        // TODO: Load and attach eBPF program
        Ok(())
    }
    
    /// Attach /proc/[pid]/mem write hook
    fn attach_proc_mem_write_hook(&self) -> Result<(), String> {
        log::info!("Attaching /proc/mem write hook");
        // TODO: Hook openat + write on /proc/*/mem paths
        Ok(())
    }
    
    /// Attach /dev/shm execution hook
    fn attach_shm_exec_hook(&self) -> Result<(), String> {
        log::info!("Attaching /dev/shm exec hook");
        // TODO: Hook execve on /dev/shm/* paths
        Ok(())
    }
    
    /// Poll for new events
    pub fn poll_events(&mut self) -> Vec<FilelessEbpfEvent> {
        // TODO: Read from eBPF ring buffer
        // For now, return buffered events
        std::mem::take(&mut self.event_buffer)
    }
    
    /// Cleanup and detach all hooks
    pub fn cleanup(&mut self) -> Result<(), String> {
        log::info!("Cleaning up fileless detection eBPF hooks");
        // TODO: Detach all eBPF programs
        Ok(())
    }
}

impl Drop for FilelessEbpfManager {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ebpf_config_default() {
        let config = EbpfHookConfig::default();
        assert!(config.enable_memfd_create);
        assert!(config.enable_ptrace);
        assert_eq!(config.sample_rate, 1);
    }
    
    #[test]
    fn test_ebpf_manager_creation() {
        let config = EbpfHookConfig::default();
        let manager = FilelessEbpfManager::new(config);
        assert_eq!(manager.event_buffer.len(), 0);
    }
    
    #[test]
    fn test_fileless_event_type() {
        let event = FilelessEbpfEvent::MemfdCreate(MemfdCreateEvent {
            timestamp_ns: 1234567890,
            pid: 1000,
            tid: 1000,
            uid: 1000,
            gid: 1000,
            comm: "malware".to_string(),
            fd: 3,
            name: "evil".to_string(),
            flags: 0,
        });
        
        assert_eq!(event.event_type(), "memfd_create");
        assert_eq!(event.pid(), 1000);
        assert_eq!(event.timestamp_ns(), 1234567890);
    }
}
