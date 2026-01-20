//! Process Lifecycle Module
//!
//! Provides process_exit event tracking for complete process lifetime visibility.
//! Tracks process start, exit, and calculates runtime duration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Process state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessState {
    Running,
    Exited,
    Killed,
    Crashed,
    Unknown,
}

impl Default for ProcessState {
    fn default() -> Self {
        ProcessState::Unknown
    }
}

/// Process exit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExit {
    /// Process ID
    pub pid: i64,
    /// Parent process ID
    pub ppid: i64,
    /// Exit code (if normal exit)
    pub exit_code: Option<i32>,
    /// Signal number (if killed by signal)
    pub signal: Option<i32>,
    /// Exit state
    pub state: ProcessState,
    /// Process start time
    pub start_time: Option<String>,
    /// Process exit time
    pub exit_time: String,
    /// Runtime duration in milliseconds
    pub runtime_ms: Option<u64>,
    /// User ID
    pub uid: i64,
    /// Group ID
    pub gid: i64,
    /// Process name
    pub comm: Option<String>,
    /// Executable path
    pub exe: Option<String>,
    /// Command line
    pub command_line: Option<String>,
    /// Container ID
    pub container_id: Option<String>,
    /// Kubernetes namespace
    pub k8s_namespace: Option<String>,
    /// Kubernetes pod
    pub k8s_pod: Option<String>,
}

/// Process lifecycle event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLifecycleEvent {
    /// Event ID
    pub trace_id: String,
    /// Timestamp
    pub timestamp: String,
    /// Namespace ID
    pub namespace_id: String,
    /// Event type
    pub event_type: ProcessLifecycleEventType,
    /// Process ID
    pub pid: i64,
    /// Parent process ID
    pub ppid: i64,
    /// User ID
    pub uid: i64,
    /// Group ID
    pub gid: i64,
    /// Process name
    pub comm: Option<String>,
    /// Executable path
    pub exe: Option<String>,
    /// Command line (for exec events)
    pub command_line: Option<String>,
    /// Exit code (for exit events)
    pub exit_code: Option<i32>,
    /// Signal (for exit events)
    pub signal: Option<i32>,
    /// Runtime duration in ms (for exit events)
    pub runtime_ms: Option<u64>,
    /// Container ID
    pub container_id: Option<String>,
    /// Kubernetes namespace
    pub k8s_namespace: Option<String>,
    /// Kubernetes pod
    pub k8s_pod: Option<String>,
}

/// Process lifecycle event types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessLifecycleEventType {
    /// Process started (exec)
    Exec,
    /// Process forked
    Fork,
    /// Process cloned
    Clone,
    /// Process exited normally
    Exit,
    /// Process killed by signal
    Signal,
    /// Process state unknown
    Unknown,
}

/// Running process information
#[derive(Debug, Clone)]
struct RunningProcess {
    pid: i64,
    ppid: i64,
    uid: i64,
    gid: i64,
    comm: Option<String>,
    exe: Option<String>,
    command_line: Option<String>,
    container_id: Option<String>,
    k8s_namespace: Option<String>,
    k8s_pod: Option<String>,
    start_time: Instant,
    start_timestamp: String,
}

/// Process lifecycle tracker
/// Correlates process start and exit events to calculate runtime
pub struct ProcessLifecycleTracker {
    /// Running processes: pid -> process info
    running: Arc<RwLock<HashMap<i64, RunningProcess>>>,
    /// Maximum tracked processes
    max_tracked: usize,
    /// TTL for stale entries (processes that never exit)
    stale_ttl: Duration,
    /// Namespace ID
    namespace_id: String,
}

impl ProcessLifecycleTracker {
    pub fn new(namespace_id: String) -> Self {
        Self {
            running: Arc::new(RwLock::new(HashMap::new())),
            max_tracked: 100000,
            stale_ttl: Duration::from_secs(86400), // 24 hours
            namespace_id,
        }
    }

    pub fn with_limits(mut self, max_tracked: usize, stale_ttl: Duration) -> Self {
        self.max_tracked = max_tracked;
        self.stale_ttl = stale_ttl;
        self
    }

    /// Record process start (exec)
    pub fn record_exec(
        &self,
        pid: i64,
        ppid: i64,
        uid: i64,
        gid: i64,
        comm: Option<String>,
        exe: Option<String>,
        command_line: Option<String>,
        container_id: Option<String>,
        k8s_namespace: Option<String>,
        k8s_pod: Option<String>,
    ) -> ProcessLifecycleEvent {
        let now = Instant::now();
        let timestamp = chrono::Utc::now().to_rfc3339();

        let proc = RunningProcess {
            pid,
            ppid,
            uid,
            gid,
            comm: comm.clone(),
            exe: exe.clone(),
            command_line: command_line.clone(),
            container_id: container_id.clone(),
            k8s_namespace: k8s_namespace.clone(),
            k8s_pod: k8s_pod.clone(),
            start_time: now,
            start_timestamp: timestamp.clone(),
        };

        if let Ok(mut running) = self.running.write() {
            // Cleanup if at capacity
            if running.len() >= self.max_tracked {
                self.cleanup_stale(&mut running);
            }

            running.insert(pid, proc);
        }

        ProcessLifecycleEvent {
            trace_id: format!("te_{}", uuid::Uuid::new_v4()),
            timestamp,
            namespace_id: self.namespace_id.clone(),
            event_type: ProcessLifecycleEventType::Exec,
            pid,
            ppid,
            uid,
            gid,
            comm,
            exe,
            command_line,
            exit_code: None,
            signal: None,
            runtime_ms: None,
            container_id,
            k8s_namespace,
            k8s_pod,
        }
    }

    /// Record process fork
    pub fn record_fork(&self, child_pid: i64, parent_pid: i64) -> ProcessLifecycleEvent {
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Copy parent info to child
        let parent_info = if let Ok(running) = self.running.read() {
            running.get(&parent_pid).cloned()
        } else {
            None
        };

        let (uid, gid, comm, exe, container_id, k8s_namespace, k8s_pod) =
            if let Some(p) = &parent_info {
                (
                    p.uid,
                    p.gid,
                    p.comm.clone(),
                    p.exe.clone(),
                    p.container_id.clone(),
                    p.k8s_namespace.clone(),
                    p.k8s_pod.clone(),
                )
            } else {
                (0, 0, None, None, None, None, None)
            };

        let proc = RunningProcess {
            pid: child_pid,
            ppid: parent_pid,
            uid,
            gid,
            comm: comm.clone(),
            exe: exe.clone(),
            command_line: None,
            container_id: container_id.clone(),
            k8s_namespace: k8s_namespace.clone(),
            k8s_pod: k8s_pod.clone(),
            start_time: Instant::now(),
            start_timestamp: timestamp.clone(),
        };

        if let Ok(mut running) = self.running.write() {
            running.insert(child_pid, proc);
        }

        ProcessLifecycleEvent {
            trace_id: format!("te_{}", uuid::Uuid::new_v4()),
            timestamp,
            namespace_id: self.namespace_id.clone(),
            event_type: ProcessLifecycleEventType::Fork,
            pid: child_pid,
            ppid: parent_pid,
            uid,
            gid,
            comm,
            exe,
            command_line: None,
            exit_code: None,
            signal: None,
            runtime_ms: None,
            container_id,
            k8s_namespace,
            k8s_pod,
        }
    }

    /// Record process exit
    pub fn record_exit(
        &self,
        pid: i64,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> ProcessLifecycleEvent {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let now = Instant::now();

        // Get process info and calculate runtime
        let proc_info = if let Ok(mut running) = self.running.write() {
            running.remove(&pid)
        } else {
            None
        };

        let (
            ppid,
            uid,
            gid,
            comm,
            exe,
            command_line,
            container_id,
            k8s_namespace,
            k8s_pod,
            runtime_ms,
        ) = if let Some(p) = proc_info {
            let runtime = now.duration_since(p.start_time).as_millis() as u64;
            (
                p.ppid,
                p.uid,
                p.gid,
                p.comm,
                p.exe,
                p.command_line,
                p.container_id,
                p.k8s_namespace,
                p.k8s_pod,
                Some(runtime),
            )
        } else {
            (0, 0, 0, None, None, None, None, None, None, None)
        };

        let event_type = if signal.is_some() {
            ProcessLifecycleEventType::Signal
        } else {
            ProcessLifecycleEventType::Exit
        };

        ProcessLifecycleEvent {
            trace_id: format!("te_{}", uuid::Uuid::new_v4()),
            timestamp,
            namespace_id: self.namespace_id.clone(),
            event_type,
            pid,
            ppid,
            uid,
            gid,
            comm,
            exe,
            command_line,
            exit_code,
            signal,
            runtime_ms,
            container_id,
            k8s_namespace,
            k8s_pod,
        }
    }

    /// Get running process info
    pub fn get_process(&self, pid: i64) -> Option<ProcessLifecycleEvent> {
        if let Ok(running) = self.running.read() {
            if let Some(p) = running.get(&pid) {
                return Some(ProcessLifecycleEvent {
                    trace_id: format!("te_{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    namespace_id: self.namespace_id.clone(),
                    event_type: ProcessLifecycleEventType::Unknown,
                    pid: p.pid,
                    ppid: p.ppid,
                    uid: p.uid,
                    gid: p.gid,
                    comm: p.comm.clone(),
                    exe: p.exe.clone(),
                    command_line: p.command_line.clone(),
                    exit_code: None,
                    signal: None,
                    runtime_ms: Some(p.start_time.elapsed().as_millis() as u64),
                    container_id: p.container_id.clone(),
                    k8s_namespace: p.k8s_namespace.clone(),
                    k8s_pod: p.k8s_pod.clone(),
                });
            }
        }
        None
    }

    /// Get count of tracked processes
    pub fn tracked_count(&self) -> usize {
        if let Ok(running) = self.running.read() {
            running.len()
        } else {
            0
        }
    }

    /// Cleanup stale entries
    fn cleanup_stale(&self, running: &mut HashMap<i64, RunningProcess>) {
        let now = Instant::now();
        running.retain(|_, v| now.duration_since(v.start_time) < self.stale_ttl);
    }

    /// Force cleanup of stale entries
    pub fn cleanup(&self) {
        if let Ok(mut running) = self.running.write() {
            self.cleanup_stale(&mut running);
        }
    }
}

/// Process tree builder
/// Builds parent-child relationships for process visualization
pub struct ProcessTree {
    /// Process nodes: pid -> node
    nodes: HashMap<i64, ProcessNode>,
}

/// Process tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: i64,
    pub ppid: i64,
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub uid: i64,
    pub start_time: Option<String>,
    pub exit_time: Option<String>,
    pub exit_code: Option<i32>,
    pub children: Vec<i64>,
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Add a process to the tree
    pub fn add_process(
        &mut self,
        pid: i64,
        ppid: i64,
        comm: Option<String>,
        exe: Option<String>,
        uid: i64,
        start_time: Option<String>,
    ) {
        let node = ProcessNode {
            pid,
            ppid,
            comm,
            exe,
            uid,
            start_time,
            exit_time: None,
            exit_code: None,
            children: Vec::new(),
        };

        self.nodes.insert(pid, node);

        // Add as child to parent
        if let Some(parent) = self.nodes.get_mut(&ppid) {
            if !parent.children.contains(&pid) {
                parent.children.push(pid);
            }
        }
    }

    /// Record process exit
    pub fn record_exit(&mut self, pid: i64, exit_time: String, exit_code: Option<i32>) {
        if let Some(node) = self.nodes.get_mut(&pid) {
            node.exit_time = Some(exit_time);
            node.exit_code = exit_code;
        }
    }

    /// Get process node
    pub fn get(&self, pid: i64) -> Option<&ProcessNode> {
        self.nodes.get(&pid)
    }

    /// Get children of a process
    pub fn children(&self, pid: i64) -> Vec<&ProcessNode> {
        if let Some(node) = self.nodes.get(&pid) {
            node.children
                .iter()
                .filter_map(|child_pid| self.nodes.get(child_pid))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get ancestors of a process (parent chain)
    pub fn ancestors(&self, pid: i64) -> Vec<&ProcessNode> {
        let mut result = Vec::new();
        let mut current_pid = pid;

        while let Some(node) = self.nodes.get(&current_pid) {
            if node.ppid == 0 || node.ppid == current_pid {
                break;
            }
            if let Some(parent) = self.nodes.get(&node.ppid) {
                result.push(parent);
                current_pid = node.ppid;
            } else {
                break;
            }
        }

        result
    }

    /// Get all descendants of a process
    pub fn descendants(&self, pid: i64) -> Vec<&ProcessNode> {
        let mut result = Vec::new();
        let mut stack = vec![pid];

        while let Some(current) = stack.pop() {
            if let Some(node) = self.nodes.get(&current) {
                for child_pid in &node.children {
                    if let Some(child) = self.nodes.get(child_pid) {
                        result.push(child);
                        stack.push(*child_pid);
                    }
                }
            }
        }

        result
    }

    /// Get root processes (ppid = 0 or parent not in tree)
    pub fn roots(&self) -> Vec<&ProcessNode> {
        self.nodes
            .values()
            .filter(|n| n.ppid == 0 || !self.nodes.contains_key(&n.ppid))
            .collect()
    }

    /// Export tree as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.nodes)
    }
}

/// /proc filesystem scanner for process exit detection
pub struct ProcExitScanner {
    /// Known PIDs
    known_pids: Arc<RwLock<HashMap<i64, Instant>>>,
    /// Proc filesystem root
    proc_root: String,
}

impl Default for ProcExitScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcExitScanner {
    pub fn new() -> Self {
        Self {
            known_pids: Arc::new(RwLock::new(HashMap::new())),
            proc_root: "/proc".to_string(),
        }
    }

    pub fn with_proc_root(mut self, root: String) -> Self {
        self.proc_root = root;
        self
    }

    /// Scan /proc for current PIDs
    pub fn scan_current_pids(&self) -> Vec<i64> {
        let mut pids = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&self.proc_root) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(pid) = name.parse::<i64>() {
                        pids.push(pid);
                    }
                }
            }
        }

        pids
    }

    /// Detect exited processes by comparing with known PIDs
    pub fn detect_exits(&self) -> Vec<i64> {
        let current_pids: std::collections::HashSet<i64> =
            self.scan_current_pids().into_iter().collect();
        let mut exited = Vec::new();

        if let Ok(mut known) = self.known_pids.write() {
            // Find PIDs that are no longer running
            for pid in known.keys().cloned().collect::<Vec<_>>() {
                if !current_pids.contains(&pid) {
                    exited.push(pid);
                }
            }

            // Remove exited PIDs
            for pid in &exited {
                known.remove(pid);
            }

            // Add new PIDs
            let now = Instant::now();
            for pid in current_pids {
                known.entry(pid).or_insert(now);
            }
        }

        exited
    }

    /// Initialize with current running processes
    pub fn initialize(&self) {
        let pids = self.scan_current_pids();
        let now = Instant::now();

        if let Ok(mut known) = self.known_pids.write() {
            for pid in pids {
                known.insert(pid, now);
            }
        }
    }
}

/// Signal name mapping
pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        16 => "SIGSTKFLT",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        23 => "SIGURG",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        26 => "SIGVTALRM",
        27 => "SIGPROF",
        28 => "SIGWINCH",
        29 => "SIGIO",
        30 => "SIGPWR",
        31 => "SIGSYS",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_lifecycle_tracking() {
        let tracker = ProcessLifecycleTracker::new("ns://test".to_string());

        // Record exec
        let exec_event = tracker.record_exec(
            1234,
            1,
            1000,
            1000,
            Some("bash".to_string()),
            Some("/bin/bash".to_string()),
            Some("bash -c 'echo hello'".to_string()),
            None,
            None,
            None,
        );

        assert_eq!(exec_event.pid, 1234);
        assert_eq!(exec_event.event_type, ProcessLifecycleEventType::Exec);
        assert_eq!(tracker.tracked_count(), 1);

        // Small delay to ensure runtime > 0
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Record exit
        let exit_event = tracker.record_exit(1234, Some(0), None);

        assert_eq!(exit_event.pid, 1234);
        assert_eq!(exit_event.event_type, ProcessLifecycleEventType::Exit);
        assert_eq!(exit_event.exit_code, Some(0));
        assert!(exit_event.runtime_ms.unwrap() >= 10);
        assert_eq!(tracker.tracked_count(), 0);
    }

    #[test]
    fn test_process_fork_tracking() {
        let tracker = ProcessLifecycleTracker::new("ns://test".to_string());

        // Record parent exec
        tracker.record_exec(
            100,
            1,
            1000,
            1000,
            Some("parent".to_string()),
            Some("/bin/parent".to_string()),
            None,
            Some("container123".to_string()),
            Some("default".to_string()),
            Some("pod-xyz".to_string()),
        );

        // Record fork
        let fork_event = tracker.record_fork(101, 100);

        assert_eq!(fork_event.pid, 101);
        assert_eq!(fork_event.ppid, 100);
        assert_eq!(fork_event.event_type, ProcessLifecycleEventType::Fork);
        // Should inherit container info from parent
        assert_eq!(fork_event.container_id, Some("container123".to_string()));
        assert_eq!(fork_event.k8s_namespace, Some("default".to_string()));
    }

    #[test]
    fn test_process_tree() {
        let mut tree = ProcessTree::new();

        // Build tree: init(1) -> bash(100) -> curl(101)
        tree.add_process(1, 0, Some("init".to_string()), None, 0, None);
        tree.add_process(
            100,
            1,
            Some("bash".to_string()),
            Some("/bin/bash".to_string()),
            1000,
            None,
        );
        tree.add_process(
            101,
            100,
            Some("curl".to_string()),
            Some("/usr/bin/curl".to_string()),
            1000,
            None,
        );

        // Check relationships
        let bash = tree.get(100).unwrap();
        assert_eq!(bash.children, vec![101]);

        let ancestors = tree.ancestors(101);
        assert_eq!(ancestors.len(), 2);
        assert_eq!(ancestors[0].pid, 100); // bash
        assert_eq!(ancestors[1].pid, 1); // init

        let descendants = tree.descendants(1);
        assert_eq!(descendants.len(), 2);

        let roots = tree.roots();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].pid, 1);
    }

    #[test]
    fn test_signal_killed_process() {
        let tracker = ProcessLifecycleTracker::new("ns://test".to_string());

        tracker.record_exec(
            200,
            1,
            1000,
            1000,
            Some("long_running".to_string()),
            None,
            None,
            None,
            None,
            None,
        );

        // Process killed by SIGKILL
        let exit_event = tracker.record_exit(200, None, Some(9));

        assert_eq!(exit_event.event_type, ProcessLifecycleEventType::Signal);
        assert_eq!(exit_event.signal, Some(9));
        assert_eq!(signal_name(9), "SIGKILL");
    }

    #[test]
    fn test_signal_names() {
        assert_eq!(signal_name(1), "SIGHUP");
        assert_eq!(signal_name(9), "SIGKILL");
        assert_eq!(signal_name(15), "SIGTERM");
        assert_eq!(signal_name(11), "SIGSEGV");
        assert_eq!(signal_name(999), "UNKNOWN");
    }
}
