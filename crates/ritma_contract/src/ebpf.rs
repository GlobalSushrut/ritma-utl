//! eBPF program suite types (4.x)
//!
//! This module defines types for eBPF program management, PID/cgroup attribution,
//! and probe tamper detection.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// eBPF program type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EbpfProgramType {
    /// Tracepoint program
    Tracepoint = 0,
    /// Kprobe program
    Kprobe = 1,
    /// Kretprobe program
    Kretprobe = 2,
    /// LSM program
    Lsm = 3,
    /// Raw tracepoint
    RawTracepoint = 4,
    /// Perf event
    PerfEvent = 5,
    /// XDP program
    Xdp = 6,
    /// Socket filter
    SocketFilter = 7,
}

impl EbpfProgramType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tracepoint => "tracepoint",
            Self::Kprobe => "kprobe",
            Self::Kretprobe => "kretprobe",
            Self::Lsm => "lsm",
            Self::RawTracepoint => "raw_tracepoint",
            Self::PerfEvent => "perf_event",
            Self::Xdp => "xdp",
            Self::SocketFilter => "socket_filter",
        }
    }
}

/// eBPF program status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProgramStatus {
    /// Not loaded
    Unloaded = 0,
    /// Loaded but not attached
    Loaded = 1,
    /// Attached and running
    Attached = 2,
    /// Detached (was running)
    Detached = 3,
    /// Error state
    Error = 4,
}

impl ProgramStatus {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unloaded => "unloaded",
            Self::Loaded => "loaded",
            Self::Attached => "attached",
            Self::Detached => "detached",
            Self::Error => "error",
        }
    }
}

/// eBPF program definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfProgram {
    pub program_id: String,
    pub program_type: EbpfProgramType,
    pub name: String,
    pub attach_point: String,
    pub bytecode_hash: [u8; 32],
    pub status: ProgramStatus,
    pub loaded_ts: Option<i64>,
    pub attached_ts: Option<i64>,
    pub event_count: u64,
    pub error: Option<String>,
}

impl EbpfProgram {
    pub fn new(program_type: EbpfProgramType, name: &str, attach_point: &str, bytecode: &[u8]) -> Self {
        let bytecode_hash = Sha256::digest(bytecode).into();
        let program_id = format!(
            "{}-{}-{}",
            program_type.name(),
            name,
            &hex::encode(bytecode_hash)[..8]
        );

        Self {
            program_id,
            program_type,
            name: name.to_string(),
            attach_point: attach_point.to_string(),
            bytecode_hash,
            status: ProgramStatus::Unloaded,
            loaded_ts: None,
            attached_ts: None,
            event_count: 0,
            error: None,
        }
    }

    pub fn mark_loaded(&mut self) {
        self.status = ProgramStatus::Loaded;
        self.loaded_ts = Some(chrono::Utc::now().timestamp());
    }

    pub fn mark_attached(&mut self) {
        self.status = ProgramStatus::Attached;
        self.attached_ts = Some(chrono::Utc::now().timestamp());
    }

    pub fn mark_error(&mut self, error: &str) {
        self.status = ProgramStatus::Error;
        self.error = Some(error.to_string());
    }

    pub fn increment_events(&mut self, count: u64) {
        self.event_count += count;
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-ebpf-prog@0.1",
            &self.program_id,
            self.program_type.name(),
            &self.name,
            &self.attach_point,
            hex::encode(self.bytecode_hash),
            self.status.name(),
            self.loaded_ts,
            self.attached_ts,
            self.event_count,
            self.error.as_deref(),
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// PID/cgroup attribution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribution {
    pub pid: i64,
    pub tgid: i64,
    pub ppid: i64,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub cgroup_id: u64,
    pub cgroup_path: Option<String>,
    pub container_id: Option<String>,
    pub namespace_id: u64,
    pub start_time_ns: u64,
}

impl Attribution {
    pub fn new(pid: i64, tgid: i64, ppid: i64, uid: u32, gid: u32, comm: &str) -> Self {
        Self {
            pid,
            tgid,
            ppid,
            uid,
            gid,
            comm: comm.to_string(),
            cgroup_id: 0,
            cgroup_path: None,
            container_id: None,
            namespace_id: 0,
            start_time_ns: 0,
        }
    }

    pub fn with_cgroup(mut self, cgroup_id: u64, cgroup_path: &str) -> Self {
        self.cgroup_id = cgroup_id;
        self.cgroup_path = Some(cgroup_path.to_string());
        self
    }

    pub fn with_container(mut self, container_id: &str) -> Self {
        self.container_id = Some(container_id.to_string());
        self
    }

    pub fn with_namespace(mut self, namespace_id: u64) -> Self {
        self.namespace_id = namespace_id;
        self
    }

    pub fn with_start_time(mut self, start_time_ns: u64) -> Self {
        self.start_time_ns = start_time_ns;
        self
    }

    /// Compute unique process key for deduplication
    pub fn process_key(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-proc-key@0.1");
        h.update(self.pid.to_le_bytes());
        h.update(self.start_time_ns.to_le_bytes());
        h.update(self.namespace_id.to_le_bytes());
        h.finalize().into()
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-attribution@0.1",
            self.pid,
            self.tgid,
            self.ppid,
            self.uid,
            self.gid,
            &self.comm,
            self.cgroup_id,
            self.cgroup_path.as_deref(),
            self.container_id.as_deref(),
            self.namespace_id,
            self.start_time_ns,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Probe tamper detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperEvent {
    pub event_id: [u8; 32],
    pub timestamp: i64,
    pub tamper_type: TamperType,
    pub program_id: Option<String>,
    pub details: String,
    pub severity: u8,
    pub auto_healed: bool,
}

/// Types of tamper detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TamperType {
    /// Program was unloaded unexpectedly
    ProgramUnloaded = 0,
    /// Program bytecode was modified
    BytecodeModified = 1,
    /// Attach point was changed
    AttachPointChanged = 2,
    /// Map data was corrupted
    MapCorrupted = 3,
    /// Ring buffer overflow
    RingBufferOverflow = 4,
    /// Kernel module unloaded
    ModuleUnloaded = 5,
    /// Syscall table modified
    SyscallTableModified = 6,
    /// IDT modified
    IdtModified = 7,
}

impl TamperType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ProgramUnloaded => "program_unloaded",
            Self::BytecodeModified => "bytecode_modified",
            Self::AttachPointChanged => "attach_point_changed",
            Self::MapCorrupted => "map_corrupted",
            Self::RingBufferOverflow => "ring_buffer_overflow",
            Self::ModuleUnloaded => "module_unloaded",
            Self::SyscallTableModified => "syscall_table_modified",
            Self::IdtModified => "idt_modified",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            Self::SyscallTableModified => 10,
            Self::IdtModified => 10,
            Self::BytecodeModified => 9,
            Self::ProgramUnloaded => 8,
            Self::ModuleUnloaded => 8,
            Self::AttachPointChanged => 7,
            Self::MapCorrupted => 6,
            Self::RingBufferOverflow => 4,
        }
    }
}

impl TamperEvent {
    pub fn new(tamper_type: TamperType, details: &str) -> Self {
        let timestamp = chrono::Utc::now().timestamp();
        let event_id = Self::compute_event_id(timestamp, tamper_type, details);

        Self {
            event_id,
            timestamp,
            tamper_type,
            program_id: None,
            details: details.to_string(),
            severity: tamper_type.severity(),
            auto_healed: false,
        }
    }

    fn compute_event_id(timestamp: i64, tamper_type: TamperType, details: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-tamper@0.1");
        h.update(timestamp.to_le_bytes());
        h.update([tamper_type as u8]);
        h.update(details.as_bytes());
        h.finalize().into()
    }

    pub fn with_program(mut self, program_id: &str) -> Self {
        self.program_id = Some(program_id.to_string());
        self
    }

    pub fn mark_healed(&mut self) {
        self.auto_healed = true;
    }

    pub fn event_id_hex(&self) -> String {
        hex::encode(self.event_id)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-tamper-event@0.1",
            hex::encode(self.event_id),
            self.timestamp,
            self.tamper_type.name(),
            self.program_id.as_deref(),
            &self.details,
            self.severity,
            self.auto_healed,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// eBPF program manager
pub struct EbpfManager {
    programs_dir: PathBuf,
    programs: HashMap<String, EbpfProgram>,
    tamper_log: Vec<TamperEvent>,
}

impl EbpfManager {
    pub fn new(out_dir: &Path) -> std::io::Result<Self> {
        let programs_dir = out_dir.join("ebpf");
        std::fs::create_dir_all(&programs_dir)?;

        Ok(Self {
            programs_dir,
            programs: HashMap::new(),
            tamper_log: Vec::new(),
        })
    }

    /// Register a program
    pub fn register_program(&mut self, program: EbpfProgram) {
        self.programs.insert(program.program_id.clone(), program);
    }

    /// Get program by ID
    pub fn get_program(&self, program_id: &str) -> Option<&EbpfProgram> {
        self.programs.get(program_id)
    }

    /// Get mutable program by ID
    pub fn get_program_mut(&mut self, program_id: &str) -> Option<&mut EbpfProgram> {
        self.programs.get_mut(program_id)
    }

    /// List all programs
    pub fn list_programs(&self) -> Vec<&EbpfProgram> {
        self.programs.values().collect()
    }

    /// Record a tamper event
    pub fn record_tamper(&mut self, event: TamperEvent) {
        self.tamper_log.push(event);
    }

    /// Get tamper events
    pub fn get_tamper_events(&self) -> &[TamperEvent] {
        &self.tamper_log
    }

    /// Check program integrity
    pub fn check_integrity(&self, program_id: &str, current_bytecode: &[u8]) -> Option<TamperEvent> {
        let program = self.programs.get(program_id)?;
        let current_hash: [u8; 32] = Sha256::digest(current_bytecode).into();

        if current_hash != program.bytecode_hash {
            Some(
                TamperEvent::new(
                    TamperType::BytecodeModified,
                    &format!("Program {} bytecode hash mismatch", program_id),
                )
                .with_program(program_id),
            )
        } else {
            None
        }
    }

    /// Save manager state
    pub fn save(&self) -> std::io::Result<()> {
        // Save programs
        let programs_path = self.programs_dir.join("programs.cbor");
        let programs: Vec<&EbpfProgram> = self.programs.values().collect();
        let mut buf = Vec::new();
        ciborium::into_writer(&programs, &mut buf).map_err(std::io::Error::other)?;
        std::fs::write(&programs_path, buf)?;

        // Save tamper log
        if !self.tamper_log.is_empty() {
            let tamper_path = self.programs_dir.join("tamper_log.cbor.zst");
            let mut buf = Vec::new();
            ciborium::into_writer(&self.tamper_log, &mut buf).map_err(std::io::Error::other)?;
            let compressed = zstd::encode_all(&buf[..], 0).map_err(std::io::Error::other)?;
            std::fs::write(&tamper_path, compressed)?;
        }

        Ok(())
    }

    /// Get health status
    pub fn health_status(&self) -> EbpfHealthStatus {
        let total = self.programs.len();
        let attached = self.programs.values().filter(|p| p.status == ProgramStatus::Attached).count();
        let errors = self.programs.values().filter(|p| p.status == ProgramStatus::Error).count();
        let tamper_count = self.tamper_log.len();

        EbpfHealthStatus {
            total_programs: total,
            attached_programs: attached,
            error_programs: errors,
            tamper_events: tamper_count,
            healthy: errors == 0 && tamper_count == 0,
        }
    }
}

/// eBPF health status
#[derive(Debug, Clone, Default)]
pub struct EbpfHealthStatus {
    pub total_programs: usize,
    pub attached_programs: usize,
    pub error_programs: usize,
    pub tamper_events: usize,
    pub healthy: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebpf_program_lifecycle() {
        let bytecode = b"fake ebpf bytecode";
        let mut prog = EbpfProgram::new(
            EbpfProgramType::Tracepoint,
            "sched_process_exec",
            "sched:sched_process_exec",
            bytecode,
        );

        assert_eq!(prog.status, ProgramStatus::Unloaded);

        prog.mark_loaded();
        assert_eq!(prog.status, ProgramStatus::Loaded);
        assert!(prog.loaded_ts.is_some());

        prog.mark_attached();
        assert_eq!(prog.status, ProgramStatus::Attached);
        assert!(prog.attached_ts.is_some());
    }

    #[test]
    fn attribution_process_key() {
        let attr1 = Attribution::new(1234, 1234, 1, 1000, 1000, "bash")
            .with_start_time(1000000)
            .with_namespace(1);

        let attr2 = Attribution::new(1234, 1234, 1, 1000, 1000, "bash")
            .with_start_time(1000000)
            .with_namespace(1);

        // Same process should have same key
        assert_eq!(attr1.process_key(), attr2.process_key());

        // Different start time = different key (pid reuse protection)
        let attr3 = Attribution::new(1234, 1234, 1, 1000, 1000, "bash")
            .with_start_time(2000000)
            .with_namespace(1);

        assert_ne!(attr1.process_key(), attr3.process_key());
    }

    #[test]
    fn tamper_event_severity() {
        assert_eq!(TamperType::SyscallTableModified.severity(), 10);
        assert!(TamperType::BytecodeModified.severity() > TamperType::RingBufferOverflow.severity());
    }

    #[test]
    fn ebpf_manager_integrity_check() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_ebpf_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let mut manager = EbpfManager::new(&tmp).unwrap();

        let bytecode = b"original bytecode";
        let prog = EbpfProgram::new(
            EbpfProgramType::Lsm,
            "file_open",
            "lsm/file_open",
            bytecode,
        );
        let prog_id = prog.program_id.clone();
        manager.register_program(prog);

        // Same bytecode = no tamper
        assert!(manager.check_integrity(&prog_id, bytecode).is_none());

        // Modified bytecode = tamper detected
        let modified = b"modified bytecode";
        let tamper = manager.check_integrity(&prog_id, modified);
        assert!(tamper.is_some());
        assert_eq!(tamper.unwrap().tamper_type, TamperType::BytecodeModified);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
