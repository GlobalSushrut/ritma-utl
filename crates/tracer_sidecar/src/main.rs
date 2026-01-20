use std::collections::{HashMap, HashSet};
use std::fs::{metadata, read_dir, read_link, read_to_string, File};
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use chrono::Utc;
use common_models::hash_string_sha256;
use common_models::{
    CausalTracer, TraceActor, TraceAttrs, TraceEvent, TraceEventKind, TraceSourceKind, TraceTarget,
};
use ebpf_provider::{EbpfProvider, TraceProviderSelector};
use index_db::IndexDb;
use ritma_contract::StorageContract;

#[derive(Debug, Clone)]
struct AuditAssemblyConfig {
    max_pending: usize,
    ttl: Duration,
    max_proctitle_bytes: usize,
    max_cwd_bytes: usize,
    max_path_bytes: usize,
    max_msg_id_len: usize,
}

impl AuditAssemblyConfig {
    fn from_env() -> Self {
        let max_pending = std::env::var("AUDIT_ASSEMBLY_MAX_PENDING")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(5000);

        let ttl_ms = std::env::var("AUDIT_ASSEMBLY_TTL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(15_000);

        let max_proctitle_bytes = std::env::var("AUDIT_PROCTITLE_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4096);

        let max_cwd_bytes = std::env::var("AUDIT_CWD_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1024);

        let max_msg_id_len = std::env::var("AUDIT_MSG_ID_MAX_LEN")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(64);

        let max_path_bytes = std::env::var("AUDIT_PATH_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4096);

        Self {
            max_pending,
            ttl: Duration::from_millis(ttl_ms),
            max_proctitle_bytes,
            max_cwd_bytes,
            max_path_bytes,
            max_msg_id_len,
        }
    }
}

fn map_audit_file_op(objtype: Option<&str>, nametype: Option<&str>) -> Option<String> {
    let obj = objtype.unwrap_or("");
    let name = nametype.unwrap_or("");
    let s = format!("{obj} {name}").to_ascii_uppercase();

    if s.contains("CREATE") {
        Some("create".to_string())
    } else if s.contains("DELETE") {
        Some("delete".to_string())
    } else if s.contains("RENAME") {
        Some("rename".to_string())
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct PendingAuditRecord {
    actor: TraceActor,
    argv_raw: Option<String>,
    cwd_raw: Option<String>,
    path_raw: Option<String>,
    inode: Option<u64>,
    file_op: Option<String>,
    kind: Option<TraceEventKind>,
    last_seen: Instant,
}

impl PendingAuditRecord {
    fn new(now: Instant) -> Self {
        Self {
            actor: TraceActor {
                pid: 0,
                ppid: 0,
                uid: 0,
                gid: 0,
                net_ns: None,
                auid: None,
                ses: None,
                tty: None,
                euid: None,
                suid: None,
                fsuid: None,
                egid: None,
                comm_hash: None,
                exe_hash: None,
                comm: None,
                exe: None,
                container_id: None,
                service: None,
                build_hash: None,
            },
            argv_raw: None,
            cwd_raw: None,
            path_raw: None,
            inode: None,
            file_op: None,
            kind: None,
            last_seen: now,
        }
    }
}

struct AuditAccumulator {
    privacy_mode: String,
    cfg: AuditAssemblyConfig,
    pending: HashMap<String, PendingAuditRecord>,
    lines_total: u64,
    completed_total: u64,
    expired_total: u64,
    overflow_dropped_total: u64,
    /// Causal tracer for ordering events
    causal_tracer: CausalTracer,
}

impl AuditAccumulator {
    fn new(privacy_mode: String) -> Self {
        Self::new_with_config(privacy_mode, AuditAssemblyConfig::from_env())
    }

    fn new_with_node_id(privacy_mode: String, node_id: String) -> Self {
        Self::new_with_config_and_node(privacy_mode, AuditAssemblyConfig::from_env(), node_id)
    }

    fn proctitle_is_priv_change(argv_raw: &str) -> bool {
        let first = argv_raw.split_whitespace().next().unwrap_or("");
        let base = first.rsplit('/').next().unwrap_or(first);
        matches!(base, "sudo" | "su")
    }

    fn new_with_config(privacy_mode: String, cfg: AuditAssemblyConfig) -> Self {
        let node_id = std::env::var("RITMA_NODE_ID").unwrap_or_else(|_| "unknown".to_string());
        Self::new_with_config_and_node(privacy_mode, cfg, node_id)
    }

    fn new_with_config_and_node(
        privacy_mode: String,
        cfg: AuditAssemblyConfig,
        node_id: String,
    ) -> Self {
        Self {
            privacy_mode,
            cfg,
            pending: HashMap::new(),
            lines_total: 0,
            completed_total: 0,
            expired_total: 0,
            overflow_dropped_total: 0,
            causal_tracer: CausalTracer::new(node_id),
        }
    }

    /// Process an audit line.
    /// - Returns Some(vec) if the line was handled by the accumulator (vec may be empty).
    /// - Returns None if caller should fall back to legacy single-line parsing.
    fn process_line(&mut self, line: &str, namespace_id: &str) -> Option<Vec<TraceEvent>> {
        self.lines_total = self.lines_total.saturating_add(1);

        let msg_id = parse_audit_msg_id(line)?;
        if msg_id.len() > self.cfg.max_msg_id_len {
            return None;
        }
        let rec_type = parse_audit_type(line);
        let now = Instant::now();

        if !self.pending.contains_key(&msg_id) {
            self.cleanup(self.cfg.ttl);
            if self.pending.len() >= self.cfg.max_pending {
                self.overflow_dropped_total = self.overflow_dropped_total.saturating_add(1);
                return None;
            }
        }

        let entry = self
            .pending
            .entry(msg_id.clone())
            .or_insert_with(|| PendingAuditRecord::new(now));
        entry.last_seen = now;

        match rec_type.as_deref() {
            Some("SYSCALL") => {
                parse_actor_fields(
                    line,
                    &mut entry.actor,
                    &self.privacy_mode,
                    self.cfg.max_path_bytes,
                );

                // Determine kind based on syscall number (best-effort) or string form.
                if let Some(syscall_s) = parse_token(line, " syscall=") {
                    if let Ok(n) = syscall_s.parse::<i64>() {
                        // x86_64 syscall numbers: execve=59, connect=42, open=2, openat=257
                        entry.kind = match n {
                            59 => Some(TraceEventKind::ProcExec),
                            42 => Some(TraceEventKind::NetConnect),
                            2 | 257 => Some(TraceEventKind::FileOpen),
                            105 | 106 | 113 | 114 | 116 | 117 | 119 | 122 | 123 => {
                                Some(TraceEventKind::PrivChange)
                            }
                            _ => entry.kind.clone(),
                        };
                    }
                }
                if entry.kind.is_none() {
                    if line.contains("syscall=execve") {
                        entry.kind = Some(TraceEventKind::ProcExec);
                    } else if line.contains("syscall=connect") {
                        entry.kind = Some(TraceEventKind::NetConnect);
                    } else if line.contains("syscall=open") || line.contains("syscall=openat") {
                        entry.kind = Some(TraceEventKind::FileOpen);
                    } else if line.contains("syscall=setuid")
                        || line.contains("syscall=setgid")
                        || line.contains("syscall=setreuid")
                        || line.contains("syscall=setregid")
                        || line.contains("syscall=setresuid")
                        || line.contains("syscall=setresgid")
                        || line.contains("syscall=setfsuid")
                        || line.contains("syscall=setfsgid")
                        || line.contains("syscall=setgroups")
                    {
                        entry.kind = Some(TraceEventKind::PrivChange);
                    }
                }

                // Only intercept ProcExec and FileOpen assembly in this slice.
                if matches!(
                    entry.kind,
                    Some(TraceEventKind::ProcExec)
                        | Some(TraceEventKind::FileOpen)
                        | Some(TraceEventKind::PrivChange)
                ) {
                    Some(vec![])
                } else {
                    None
                }
            }
            Some("PROCTITLE") => {
                if let Some(hex) = parse_token(line, " proctitle=") {
                    entry.argv_raw = decode_proctitle_hex(hex, self.cfg.max_proctitle_bytes);
                }
                Some(vec![])
            }
            Some("CWD") => {
                if let Some(cwd) = parse_token(line, " cwd=") {
                    let cwd = cwd.trim_matches('"');
                    if !cwd.is_empty() {
                        entry.cwd_raw = Some(truncate_utf8(cwd, self.cfg.max_cwd_bytes));
                    }
                }
                Some(vec![])
            }
            Some("PATH") => {
                // PATH records are part of file evidence. We always capture them (bounded),
                // then decide whether to emit based on SYSCALL kind at EOE.
                if let Some(name) = parse_token(line, " name=") {
                    let name = name.trim_matches('"');
                    if !name.is_empty() {
                        entry.path_raw = Some(truncate_utf8(name, self.cfg.max_path_bytes));
                    }
                }

                if let Some(inode_s) = parse_token(line, " inode=") {
                    entry.inode = inode_s.parse::<u64>().ok();
                }

                let objtype = parse_token(line, " objtype=");
                let nametype = parse_token(line, " nametype=");
                entry.file_op = map_audit_file_op(objtype, nametype);

                Some(vec![])
            }
            Some("EOE") => {
                let Some(kind) = entry.kind.clone() else {
                    self.pending.remove(&msg_id);
                    return Some(vec![]);
                };

                match kind {
                    TraceEventKind::ProcExec => {
                        let argv_hash = entry.argv_raw.as_ref().map(|s| hash_string_sha256(s));
                        let cwd_hash = entry.cwd_raw.as_ref().map(|s| hash_string_sha256(s));

                        let argv = if self.privacy_mode == "raw" {
                            entry.argv_raw.clone()
                        } else {
                            None
                        };
                        let cwd = if self.privacy_mode == "raw" {
                            entry.cwd_raw.clone()
                        } else {
                            None
                        };

                        let out_kind = if entry
                            .argv_raw
                            .as_ref()
                            .map(|s| Self::proctitle_is_priv_change(s))
                            .unwrap_or(false)
                        {
                            TraceEventKind::PrivChange
                        } else {
                            TraceEventKind::ProcExec
                        };

                        // Get causal metadata for this event
                        let causal_meta = self.causal_tracer.record_event();
                        let trace_id = format!("te_{}", uuid::Uuid::new_v4());

                        let te = TraceEvent {
                            trace_id: trace_id.clone(),
                            ts: chrono::Utc::now().to_rfc3339(),
                            namespace_id: namespace_id.to_string(),
                            source: TraceSourceKind::Auditd,
                            kind: out_kind,
                            actor: entry.actor.clone(),
                            target: TraceTarget {
                                path_hash: None,
                                dst: None,
                                domain_hash: None,
                                protocol: None,
                                src: None,
                                state: None,
                                dns: None,
                                path: None,
                                inode: None,
                                file_op: None,
                            },
                            attrs: TraceAttrs {
                                argv_hash,
                                cwd_hash,
                                bytes_out: None,
                                argv,
                                cwd,
                                bytes_in: None,
                                env_hash: None,
                            },
                            lamport_ts: Some(causal_meta.lamport_ts),
                            causal_parent: causal_meta.causal_parent,
                            vclock: Some(causal_meta.vclock),
                        };

                        // Update last trace_id for causal chaining
                        self.causal_tracer.set_last_trace_id(trace_id);

                        self.pending.remove(&msg_id);
                        self.completed_total = self.completed_total.saturating_add(1);
                        Some(vec![te])
                    }
                    TraceEventKind::FileOpen => {
                        let Some(path_s) = entry.path_raw.clone() else {
                            self.pending.remove(&msg_id);
                            return Some(vec![]);
                        };

                        let path_hash = Some(hash_string_sha256(&path_s));
                        let path = if self.privacy_mode == "raw" {
                            Some(path_s)
                        } else {
                            None
                        };

                        // Get causal metadata for this event
                        let causal_meta = self.causal_tracer.record_event();
                        let trace_id = format!("te_{}", uuid::Uuid::new_v4());

                        let te = TraceEvent {
                            trace_id: trace_id.clone(),
                            ts: chrono::Utc::now().to_rfc3339(),
                            namespace_id: namespace_id.to_string(),
                            source: TraceSourceKind::Auditd,
                            kind: TraceEventKind::FileOpen,
                            actor: entry.actor.clone(),
                            target: TraceTarget {
                                path_hash,
                                dst: None,
                                domain_hash: None,
                                protocol: None,
                                src: None,
                                state: None,
                                dns: None,
                                path,
                                inode: entry.inode,
                                file_op: entry.file_op.clone(),
                            },
                            attrs: TraceAttrs {
                                argv_hash: None,
                                cwd_hash: None,
                                bytes_out: None,
                                argv: None,
                                cwd: None,
                                bytes_in: None,
                                env_hash: None,
                            },
                            lamport_ts: Some(causal_meta.lamport_ts),
                            causal_parent: causal_meta.causal_parent,
                            vclock: Some(causal_meta.vclock),
                        };

                        // Update last trace_id for causal chaining
                        self.causal_tracer.set_last_trace_id(trace_id);

                        self.pending.remove(&msg_id);
                        self.completed_total = self.completed_total.saturating_add(1);
                        Some(vec![te])
                    }
                    TraceEventKind::PrivChange => {
                        // Get causal metadata for this event
                        let causal_meta = self.causal_tracer.record_event();
                        let trace_id = format!("te_{}", uuid::Uuid::new_v4());

                        let te = TraceEvent {
                            trace_id: trace_id.clone(),
                            ts: chrono::Utc::now().to_rfc3339(),
                            namespace_id: namespace_id.to_string(),
                            source: TraceSourceKind::Auditd,
                            kind: TraceEventKind::PrivChange,
                            actor: entry.actor.clone(),
                            target: TraceTarget {
                                path_hash: None,
                                dst: None,
                                domain_hash: None,
                                protocol: None,
                                src: None,
                                state: None,
                                dns: None,
                                path: None,
                                inode: None,
                                file_op: None,
                            },
                            attrs: TraceAttrs {
                                argv_hash: entry.argv_raw.as_ref().map(|s| hash_string_sha256(s)),
                                cwd_hash: entry.cwd_raw.as_ref().map(|s| hash_string_sha256(s)),
                                bytes_out: None,
                                argv: if self.privacy_mode == "raw" {
                                    entry.argv_raw.clone()
                                } else {
                                    None
                                },
                                cwd: if self.privacy_mode == "raw" {
                                    entry.cwd_raw.clone()
                                } else {
                                    None
                                },
                                bytes_in: None,
                                env_hash: None,
                            },
                            lamport_ts: Some(causal_meta.lamport_ts),
                            causal_parent: causal_meta.causal_parent,
                            vclock: Some(causal_meta.vclock),
                        };

                        // Update last trace_id for causal chaining
                        self.causal_tracer.set_last_trace_id(trace_id);

                        self.pending.remove(&msg_id);
                        self.completed_total = self.completed_total.saturating_add(1);
                        Some(vec![te])
                    }
                    _ => {
                        self.pending.remove(&msg_id);
                        Some(vec![])
                    }
                }
            }
            // EXECVE records exist, but we prefer PROCTITLE for raw argv.
            // Only intercept if we're building a ProcExec record.
            Some("EXECVE") => {
                if matches!(entry.kind, Some(TraceEventKind::ProcExec)) {
                    Some(vec![])
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn cleanup(&mut self, ttl: Duration) {
        let now = Instant::now();
        let before = self.pending.len();
        self.pending
            .retain(|_, v| now.duration_since(v.last_seen) <= ttl);
        let after = self.pending.len();
        let expired = before.saturating_sub(after) as u64;
        self.expired_total = self.expired_total.saturating_add(expired);
    }
}

fn parse_audit_msg_id(line: &str) -> Option<String> {
    let pos = line.find(" msg=audit(")?;
    let rest = &line[pos + " msg=audit(".len()..];
    let colon = rest.find(':')?;
    let after_colon = &rest[colon + 1..];
    let end = after_colon.find(')')?;
    Some(after_colon[..end].to_string())
}

fn parse_audit_type(line: &str) -> Option<String> {
    if let Some(rest) = line.strip_prefix("type=") {
        let end = rest.find(' ').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    if let Some(pos) = line.find(" type=") {
        let rest = &line[pos + " type=".len()..];
        let end = rest.find(' ').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    None
}

fn decode_proctitle_hex(hex: &str, max_bytes: usize) -> Option<String> {
    let hex = hex.trim_matches('"');
    if hex.len() < 2 || hex.len() % 2 != 0 {
        return None;
    }
    let max_pairs = std::cmp::min(hex.len() / 2, max_bytes);
    let mut bytes: Vec<u8> = Vec::with_capacity(max_pairs);
    let mut i = 0usize;
    while i + 1 < hex.len() && (bytes.len() < max_pairs) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16).ok()?;
        bytes.push(if b == 0 { b' ' } else { b });
        i += 2;
    }
    let s = String::from_utf8(bytes).ok()?;
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut cut = 0usize;
    for (i, _) in s.char_indices() {
        if i > max_bytes {
            break;
        }
        cut = i;
    }
    if cut == 0 {
        "".to_string()
    } else {
        s[..cut].to_string()
    }
}

fn parse_actor_fields(line: &str, actor: &mut TraceActor, privacy_mode: &str, max_bytes: usize) {
    if let Some(pid_s) = parse_token(line, " pid=") {
        actor.pid = pid_s.parse().unwrap_or(0);
    }
    if let Some(ppid_s) = parse_token(line, " ppid=") {
        actor.ppid = ppid_s.parse().unwrap_or(0);
    }
    if let Some(auid_s) = parse_token(line, " auid=") {
        actor.auid = auid_s.parse().ok();
    }
    if let Some(ses_s) = parse_token(line, " ses=") {
        actor.ses = ses_s.parse().ok();
    }
    if let Some(tty_s) = parse_token(line, " tty=") {
        let tty_s = tty_s.trim_matches('"');
        if !tty_s.is_empty() && tty_s != "(none)" {
            actor.tty = Some(tty_s.to_string());
        }
    }
    if let Some(uid_s) = parse_token(line, " uid=") {
        actor.uid = uid_s.parse().unwrap_or(0);
    }
    if let Some(gid_s) = parse_token(line, " gid=") {
        actor.gid = gid_s.parse().unwrap_or(0);
    }
    if let Some(euid_s) = parse_token(line, " euid=") {
        actor.euid = euid_s.parse().ok();
    }
    if let Some(suid_s) = parse_token(line, " suid=") {
        actor.suid = suid_s.parse().ok();
    }
    if let Some(fsuid_s) = parse_token(line, " fsuid=") {
        actor.fsuid = fsuid_s.parse().ok();
    }
    if let Some(egid_s) = parse_token(line, " egid=") {
        actor.egid = egid_s.parse().ok();
    }

    if let Some(comm_s) = parse_token(line, " comm=") {
        let comm_s = comm_s.trim_matches('"');
        if !comm_s.is_empty() {
            let comm_s = truncate_utf8(comm_s, max_bytes);
            actor.comm_hash = Some(hash_string_sha256(&comm_s));
            actor.comm = if privacy_mode == "raw" {
                Some(comm_s)
            } else {
                None
            };
        }
    }

    if let Some(exe_s) = parse_token(line, " exe=") {
        let exe_s = exe_s.trim_matches('"');
        if !exe_s.is_empty() {
            let exe_s = truncate_utf8(exe_s, max_bytes);
            actor.exe_hash = Some(hash_string_sha256(&exe_s));
            actor.exe = if privacy_mode == "raw" {
                Some(exe_s)
            } else {
                None
            };
        }
    }
}

fn validate_namespace(ns: &str) -> std::result::Result<(), String> {
    if ns.is_empty() {
        return Err("namespace cannot be empty".to_string());
    }
    if !ns.starts_with("ns://") {
        return Err("namespace must start with 'ns://'".to_string());
    }
    if ns.len() < "ns://a".len() {
        return Err("namespace too short".to_string());
    }
    if ns.len() > 512 {
        return Err("namespace too long (max 512 chars)".to_string());
    }
    Ok(())
}

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

fn acquire_single_instance_lock(lock_path: &Path) -> Result<Option<File>> {
    if env_truthy("RITMA_ALLOW_MULTI_SIDECAR") {
        return Ok(None);
    }

    let lock_path_s = lock_path.display().to_string();
    validate_path_str("RITMA_SIDECAR_LOCK_PATH", &lock_path_s, false)
        .map_err(std::io::Error::other)?;

    let _ = ensure_parent_dir(lock_path);

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)?;

    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(std::io::Error::other(format!(
                "tracer_sidecar already running (lock {lock_path_s}). To bypass single-writer lock set RITMA_ALLOW_MULTI_SIDECAR=1"
            ))
            .into());
        }
        return Err(std::io::Error::other(format!(
            "failed to acquire tracer_sidecar lock {lock_path_s}: {e}. Check that lock dir exists and is writable (e.g. /run/ritma/locks)"
        ))
        .into());
    }

    let _ = f.set_len(0);
    let _ = f.write_all(format!("pid={}\n", std::process::id()).as_bytes());
    let _ = f.flush();

    Ok(Some(f))
}

fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent)
}

fn validate_path_str(name: &str, p: &str, allow_relative: bool) -> std::result::Result<(), String> {
    if p.trim().is_empty() {
        return Err(format!("{name} cannot be empty"));
    }
    if p.len() > 4096 {
        return Err(format!("{name} too long"));
    }
    if p.contains('\0') {
        return Err(format!("{name} must not contain NUL"));
    }
    if p.contains("..") {
        return Err(format!("{name} must not contain '..'"));
    }
    let pb = Path::new(p);
    if !allow_relative && !pb.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(())
}

fn find_hex64(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    for i in 0..=(bytes.len() - 64) {
        let win = &bytes[i..i + 64];
        if win.iter().all(|b| b.is_ascii_hexdigit()) {
            return std::str::from_utf8(win).ok().map(|v| v.to_string());
        }
    }
    None
}

fn read_status_value_i64(contents: &str, key: &str) -> Option<i64> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            // e.g. "Uid:\t1000\t1000\t1000\t1000"
            let v = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<i64>().ok());
            return v;
        }
    }
    None
}

#[derive(Clone, Debug)]
struct ProcMetaFull {
    pid: i64,
    ppid: i64,
    uid: i64,
    gid: i64,
    net_ns: Option<u64>,
    comm: Option<String>,
    exe: Option<String>,
    comm_hash: Option<String>,
    exe_hash: Option<String>,
    container_id: Option<String>,
}

fn proc_meta(proc_root: &str, pid: i64) -> Option<ProcMetaFull> {
    let status_path = format!("{proc_root}/{pid}/status");
    let status = read_to_string(status_path).ok()?;
    let uid = read_status_value_i64(&status, "Uid:")?;
    let gid = read_status_value_i64(&status, "Gid:")?;
    let ppid = read_status_value_i64(&status, "PPid:").unwrap_or(0);

    let comm = read_to_string(format!("{proc_root}/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let exe = read_link(format!("{proc_root}/{pid}/exe"))
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty());

    let comm_hash = comm.as_ref().map(|s| hash_string_sha256(s));
    let exe_hash = exe.as_ref().map(|s| hash_string_sha256(s));

    let container_id = read_to_string(format!("{proc_root}/{pid}/cgroup"))
        .ok()
        .and_then(|s| find_hex64(&s))
        .map(|h| format!("ctr:{h}"));

    let net_ns = read_link(format!("{proc_root}/{pid}/ns/net"))
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .and_then(|s| {
            s.strip_prefix("net:[")
                .and_then(|t| t.strip_suffix(']'))
                .map(|v| v.to_string())
        })
        .and_then(|s| s.parse::<u64>().ok());

    Some(ProcMetaFull {
        pid,
        ppid,
        uid,
        gid,
        net_ns,
        comm,
        exe,
        comm_hash,
        exe_hash,
        container_id,
    })
}

fn parse_socket_inode(link: &std::path::Path) -> Option<u64> {
    // symlink target like "socket:[12345]"
    let s = link.to_str()?;
    if !s.starts_with("socket:[") {
        return None;
    }
    let inner = s.strip_prefix("socket:[")?.strip_suffix("]")?;
    inner.parse::<u64>().ok()
}

fn build_socket_inode_map(proc_root: &str) -> HashMap<u64, ProcMetaFull> {
    let mut out: HashMap<u64, ProcMetaFull> = HashMap::new();
    let root = Path::new(proc_root);
    let Ok(pids) = read_dir(root) else {
        return out;
    };

    for ent in pids.flatten() {
        let name = ent.file_name();
        let Some(pid_s) = name.to_str() else { continue };
        let Ok(pid) = pid_s.parse::<i64>() else {
            continue;
        };
        let Some(meta) = proc_meta(proc_root, pid) else {
            continue;
        };

        let fd_dir = ent.path().join("fd");
        let Ok(fds) = read_dir(fd_dir) else {
            continue;
        };

        for fdent in fds.flatten() {
            let Ok(target) = read_link(fdent.path()) else {
                continue;
            };
            if let Some(inode) = parse_socket_inode(&target) {
                // first-writer wins is fine for our purposes
                out.entry(inode).or_insert_with(|| meta.clone());
            }
        }
    }

    out
}

fn parse_token<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    // naive: find "key=" and take until space
    if let Some(pos) = line.find(key) {
        let s = &line[pos + key.len()..];
        let end = s.find(' ').unwrap_or(s.len());
        return Some(&s[..end]);
    }
    None
}

fn hex_to_ipv4_port(hex: &str) -> Option<String> {
    // format: IP(8 hex):PORT(4 hex) little-endian for IP bytes
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_hex = parts[0];
    let port_hex = parts[1];
    if ip_hex.len() != 8 {
        return None;
    }
    let b0 = u8::from_str_radix(&ip_hex[6..8], 16).ok()?;
    let b1 = u8::from_str_radix(&ip_hex[4..6], 16).ok()?;
    let b2 = u8::from_str_radix(&ip_hex[2..4], 16).ok()?;
    let b3 = u8::from_str_radix(&ip_hex[0..2], 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some(format!("{b0}.{b1}.{b2}.{b3}:{port}"))
}

fn hex_to_ipv6_port(hex: &str) -> Option<String> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_hex = parts[0];
    let port_hex = parts[1];
    if ip_hex.len() != 32 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    let mut bytes = [0u8; 16];
    for i in 0..16 {
        let off = i * 2;
        bytes[i] = u8::from_str_radix(&ip_hex[off..off + 2], 16).ok()?;
    }

    let addr = std::net::Ipv6Addr::from(bytes);
    Some(format!("[{addr}]:{port}"))
}

fn protocol_from_table(table: &str) -> Option<String> {
    if table.starts_with("tcp") {
        Some("tcp".to_string())
    } else if table.starts_with("udp") {
        Some("udp".to_string())
    } else {
        None
    }
}

fn state_from_table(table: &str, state_hex: Option<&str>) -> Option<String> {
    if table.starts_with("tcp") {
        state_hex.and_then(map_tcp_state)
    } else {
        None
    }
}

fn parse_tx_rx_queues(col: Option<&str>) -> (Option<i64>, Option<i64>) {
    let Some(s) = col else {
        return (None, None);
    };
    let mut it = s.split(':');
    let tx = it.next().and_then(|h| i64::from_str_radix(h, 16).ok());
    let rx = it.next().and_then(|h| i64::from_str_radix(h, 16).ok());
    (tx, rx)
}

fn src_from_privacy_mode(privacy_mode: &str, src_full: &str) -> Option<String> {
    if privacy_mode == "raw" {
        Some(src_full.to_string())
    } else {
        None
    }
}

fn map_tcp_state(state_hex: &str) -> Option<String> {
    match state_hex.to_ascii_uppercase().as_str() {
        "01" => Some("ESTABLISHED".to_string()),
        "02" => Some("SYN_SENT".to_string()),
        "03" => Some("SYN_RECV".to_string()),
        "04" => Some("FIN_WAIT1".to_string()),
        "05" => Some("FIN_WAIT2".to_string()),
        "06" => Some("TIME_WAIT".to_string()),
        "07" => Some("CLOSE".to_string()),
        "08" => Some("CLOSE_WAIT".to_string()),
        "09" => Some("LAST_ACK".to_string()),
        "0A" => Some("LISTEN".to_string()),
        "0B" => Some("CLOSING".to_string()),
        "0C" => Some("NEW_SYN_RECV".to_string()),
        _ => None,
    }
}

fn scan_proc_net_egress(
    index_path: String,
    namespace_id: String,
    proc_root: String,
    interval_secs: u64,
) -> Result<()> {
    let index = IndexDb::open(&index_path)?;
    let privacy_mode = std::env::var("PRIVACY_MODE").unwrap_or_else(|_| "hash-only".to_string());
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        let inode_map = build_socket_inode_map(&proc_root);

        let tables: [(&str, fn(&str) -> Option<String>); 4] = [
            ("tcp", hex_to_ipv4_port),
            ("tcp6", hex_to_ipv6_port),
            ("udp", hex_to_ipv4_port),
            ("udp6", hex_to_ipv6_port),
        ];

        for (table, parse_addr) in tables {
            let path = format!("{proc_root}/net/{table}");
            let Ok(s) = read_to_string(&path) else {
                continue;
            };

            for (i, line) in s.lines().enumerate() {
                if i == 0 {
                    continue;
                }
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() > 9 {
                    let Some(src_full) = parse_addr(cols[1]) else {
                        continue;
                    };
                    let Some(dst) = parse_addr(cols[2]) else {
                        continue;
                    };
                    let state_hex = cols.get(3).copied();
                    let (bytes_out, bytes_in) = parse_tx_rx_queues(cols.get(4).copied());
                    let inode = cols[9].parse::<u64>().ok();
                    let meta = inode.and_then(|ino| inode_map.get(&ino).cloned());

                    let (pid, ppid, uid, gid, net_ns, comm_hash, exe_hash, comm, exe, container_id) =
                        if let Some(m) = meta {
                            (
                                m.pid,
                                m.ppid,
                                m.uid,
                                m.gid,
                                m.net_ns,
                                m.comm_hash.clone(),
                                m.exe_hash.clone(),
                                m.comm.clone(),
                                m.exe.clone(),
                                m.container_id.clone(),
                            )
                        } else {
                            (0, 0, 0, 0, None, None, None, None, None, None)
                        };

                    let seen_key = format!("{table}:{pid}:{dst}");
                    if !seen.insert(seen_key) {
                        continue;
                    }

                    let (dst_opt, domain_hash_opt) = if privacy_mode == "raw" {
                        (Some(dst.clone()), Some(hash_string_sha256(&dst)))
                    } else {
                        (None, Some(hash_string_sha256(&dst)))
                    };

                    let src_opt = src_from_privacy_mode(&privacy_mode, &src_full);
                    let protocol = protocol_from_table(table);
                    let state = state_from_table(table, state_hex);

                    let te = TraceEvent {
                        trace_id: format!("te_{}", uuid::Uuid::new_v4()),
                        ts: Utc::now().to_rfc3339(),
                        namespace_id: namespace_id.clone(),
                        source: TraceSourceKind::Runtime,
                        kind: TraceEventKind::NetConnect,
                        actor: TraceActor {
                            pid,
                            ppid,
                            uid,
                            gid,
                            net_ns,
                            auid: None,
                            ses: None,
                            tty: None,
                            euid: None,
                            suid: None,
                            fsuid: None,
                            egid: None,
                            comm_hash,
                            exe_hash,
                            comm: if privacy_mode == "raw" { comm } else { None },
                            exe: if privacy_mode == "raw" { exe } else { None },
                            container_id,
                            service: None,
                            build_hash: None,
                        },
                        target: TraceTarget {
                            path_hash: None,
                            dst: dst_opt,
                            domain_hash: domain_hash_opt,
                            protocol,
                            src: src_opt,
                            state,
                            dns: None,
                            path: None,
                            inode: None,
                            file_op: None,
                        },
                        attrs: TraceAttrs {
                            argv_hash: None,
                            cwd_hash: None,
                            bytes_out,
                            argv: None,
                            cwd: None,
                            bytes_in,
                            env_hash: None,
                        },
                        lamport_ts: None,
                        causal_parent: None,
                        vclock: None,
                    };
                    let _ = index.insert_trace_event_from_model(&te);
                }
            }
        }
        sleep(Duration::from_secs(interval_secs));
    }
}

fn map_line_to_trace(line: &str, namespace_id: &str) -> Option<TraceEvent> {
    // Very conservative parsing for auditd lines; handle a few high-signal cases
    let ts = Utc::now().to_rfc3339();

    let privacy_mode = std::env::var("PRIVACY_MODE").unwrap_or_else(|_| "hash-only".to_string());

    // Defaults
    let mut actor = TraceActor {
        pid: 0,
        ppid: 0,
        uid: 0,
        gid: 0,
        net_ns: None,
        auid: None,
        ses: None,
        tty: None,
        euid: None,
        suid: None,
        fsuid: None,
        egid: None,
        comm_hash: None,
        exe_hash: None,
        comm: None,
        exe: None,
        container_id: None,
        service: None,
        build_hash: None,
    };
    parse_actor_fields(line, &mut actor, &privacy_mode, 4096);

    // FILE_OPEN via PATH name= and SYSCALL open/openat
    if (line.contains("type=PATH") || line.contains("name="))
        && (line.contains(" open") || line.contains(" openat"))
    {
        let path_hash = parse_token(line, " name=")
            .map(|s| s.trim_matches('"'))
            .map(hash_string_sha256);
        let te = TraceEvent {
            trace_id: format!("te_{}", uuid::Uuid::new_v4()),
            ts: ts.clone(),
            namespace_id: namespace_id.to_string(),
            source: TraceSourceKind::Auditd,
            kind: TraceEventKind::FileOpen,
            actor,
            target: TraceTarget {
                path_hash,
                dst: None,
                domain_hash: None,
                protocol: None,
                src: None,
                state: None,
                dns: None,
                path: None,
                inode: None,
                file_op: None,
            },
            attrs: TraceAttrs {
                argv_hash: None,
                cwd_hash: None,
                bytes_out: None,
                argv: None,
                cwd: None,
                bytes_in: None,
                env_hash: None,
            },
            lamport_ts: None,
            causal_parent: None,
            vclock: None,
        };
        return Some(te);
    }

    // PROC_EXEC via EXECVE
    if line.contains("type=EXECVE")
        || (line.contains("type=SYSCALL") && line.contains("syscall=execve"))
    {
        let argv_hash = parse_token(line, " argc=").map(|_| hash_string_sha256(line));
        let te = TraceEvent {
            trace_id: format!("te_{}", uuid::Uuid::new_v4()),
            ts: ts.clone(),
            namespace_id: namespace_id.to_string(),
            source: TraceSourceKind::Auditd,
            kind: TraceEventKind::ProcExec,
            actor,
            target: TraceTarget {
                path_hash: None,
                dst: None,
                domain_hash: None,
                protocol: None,
                src: None,
                state: None,
                dns: None,
                path: None,
                inode: None,
                file_op: None,
            },
            attrs: TraceAttrs {
                argv_hash,
                cwd_hash: None,
                bytes_out: None,
                argv: None,
                cwd: None,
                bytes_in: None,
                env_hash: None,
            },
            lamport_ts: None,
            causal_parent: None,
            vclock: None,
        };
        return Some(te);
    }

    // NET_CONNECT via SYSCALL connect
    if line.contains("type=SYSCALL") && line.contains("syscall=connect") {
        let te = TraceEvent {
            trace_id: format!("te_{}", uuid::Uuid::new_v4()),
            ts: ts.clone(),
            namespace_id: namespace_id.to_string(),
            source: TraceSourceKind::Auditd,
            kind: TraceEventKind::NetConnect,
            actor,
            target: TraceTarget {
                path_hash: None,
                dst: None,
                domain_hash: None,
                protocol: None,
                src: None,
                state: None,
                dns: None,
                path: None,
                inode: None,
                file_op: None,
            },
            attrs: TraceAttrs {
                argv_hash: None,
                cwd_hash: None,
                bytes_out: None,
                argv: None,
                cwd: None,
                bytes_in: None,
                env_hash: None,
            },
            lamport_ts: None,
            causal_parent: None,
            vclock: None,
        };
        return Some(te);
    }

    None
}

fn tail_file_to_indexdb(index: &IndexDb, path: &str, namespace_id: &str) -> Result<()> {
    let mut offset: u64 = 0;
    let privacy_mode = std::env::var("PRIVACY_MODE").unwrap_or_else(|_| "hash-only".to_string());
    let mut acc = AuditAccumulator::new(privacy_mode);
    loop {
        let meta = metadata(path);
        if let Ok(meta) = meta {
            let len = meta.len();
            if len < offset {
                offset = 0;
            }
            if len > offset {
                let mut file = File::open(path)?;
                file.seek(std::io::SeekFrom::Start(offset))?;
                let mut buf = String::new();
                file.read_to_string(&mut buf)?;
                offset = len;
                for line in buf.lines() {
                    // First try the multi-line assembler for ProcExec enrichment.
                    if let Some(events) = acc.process_line(line, namespace_id) {
                        for te in events {
                            let _ = index.insert_trace_event_from_model(&te);
                        }
                        continue;
                    }
                    // Fall back to legacy single-line parsing for other event types.
                    if let Some(te) = map_line_to_trace(line, namespace_id) {
                        let _ = index.insert_trace_event_from_model(&te);
                    }
                }

                // Cleanup old in-flight records to avoid unbounded growth.
                acc.cleanup(acc.cfg.ttl);
            }
        }
        sleep(Duration::from_secs(1));
    }
}

fn main() -> Result<()> {
    let namespace_id =
        std::env::var("NAMESPACE_ID").unwrap_or_else(|_| "ns://demo/dev/hello/world".to_string());
    validate_namespace(&namespace_id)
        .map_err(|e| std::io::Error::other(format!("invalid NAMESPACE_ID: {e}")))?;

    let contract = StorageContract::resolve_cctv()
        .map_err(|e| std::io::Error::other(format!("storage contract: {e}")))?;

    let _lock = acquire_single_instance_lock(&contract.tracer_lock_path())?;

    contract
        .ensure_base_dir()
        .map_err(|e| std::io::Error::other(format!("ensure base dir: {e}")))?;
    contract
        .ensure_out_layout()
        .map_err(|e| std::io::Error::other(format!("ensure RITMA_OUT layout: {e}")))?;

    let audit_path =
        std::env::var("AUDIT_LOG_PATH").unwrap_or_else(|_| "/var/log/audit/audit.log".to_string());
    validate_path_str("AUDIT_LOG_PATH", &audit_path, false).map_err(std::io::Error::other)?;

    let index_path = contract.index_db_path.display().to_string();
    validate_path_str("INDEX_DB_PATH", &index_path, true).map_err(std::io::Error::other)?;
    if !index_path.ends_with(".sqlite") {
        return Err(std::io::Error::other("INDEX_DB_PATH must end with .sqlite").into());
    }

    ensure_parent_dir(&contract.index_db_path)?;

    let proc_root = std::env::var("PROC_ROOT").unwrap_or_else(|_| "/proc".to_string());
    validate_path_str("PROC_ROOT", &proc_root, false).map_err(std::io::Error::other)?;

    let net_scan_secs: u64 = match std::env::var("NET_SCAN_INTERVAL_SECS") {
        Ok(s) => s
            .parse::<u64>()
            .map_err(|e| std::io::Error::other(format!("invalid NET_SCAN_INTERVAL_SECS: {e}")))?,
        Err(_) => 30,
    };
    if !(1..=3600).contains(&net_scan_secs) {
        return Err(std::io::Error::other("NET_SCAN_INTERVAL_SECS must be 1..=3600").into());
    }

    let selected = TraceProviderSelector::select_best();
    if selected == "ebpf" {
        let ns = namespace_id.clone();
        let idx = index_path.clone();
        spawn(move || {
            eprintln!("tracer_sidecar[ebpf]: starting for {ns}");
            let mut p = EbpfProvider::new(ns, idx);
            if let Err(e) = p.start() {
                eprintln!("tracer_sidecar[ebpf]: init error: {e}");
                return;
            }
            eprintln!("tracer_sidecar[ebpf]: active");
            loop {
                sleep(Duration::from_secs(3600));
            }
        });
    }

    if selected != "ebpf" {
        // Thread 1: auditd tail (fallback)
        {
            let ns = namespace_id.clone();
            let idx = index_path.clone();
            let ap = audit_path.clone();
            spawn(move || match IndexDb::open(&idx) {
                Ok(index) => {
                    eprintln!("tracer_sidecar[auditd]: tailing {ap} for {ns}");
                    let _ = tail_file_to_indexdb(&index, &ap, &ns);
                }
                Err(e) => eprintln!("tracer_sidecar[auditd]: init error: {e}"),
            });
        }

        // Thread 2: proc net egress scanner
        {
            let ns = namespace_id.clone();
            let idx = index_path.clone();
            let pr = proc_root.clone();
            spawn(move || {
                eprintln!("tracer_sidecar[proc]: scanning {pr} every {net_scan_secs}s");
                let _ = scan_proc_net_egress(idx, ns, pr, net_scan_secs);
            });
        }
    }

    // Keep main alive
    loop {
        sleep(Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_for_test() -> AuditAssemblyConfig {
        AuditAssemblyConfig {
            max_pending: 128,
            ttl: Duration::from_millis(15_000),
            max_proctitle_bytes: 4096,
            max_cwd_bytes: 1024,
            max_path_bytes: 4096,
            max_msg_id_len: 64,
        }
    }

    #[test]
    fn audit_assembler_proc_exec_hash_only() {
        let mut acc = AuditAccumulator::new_with_config("hash-only".to_string(), cfg_for_test());
        let ns = "ns://test";

        let lines = [
            "type=SYSCALL msg=audit(1700000000.123:555): arch=c000003e syscall=59 pid=123 ppid=1 uid=1000 gid=1000 auid=1000 ses=1 tty=\"pts0\" euid=1000 suid=1000 fsuid=1000 egid=1000 comm=\"echo\" exe=\"/bin/echo\"",
            "type=PROCTITLE msg=audit(1700000000.123:555): proctitle=2f62696e2f6563686f0068656c6c6f",
            "type=CWD msg=audit(1700000000.123:555): cwd=\"/tmp\"",
            "type=EOE msg=audit(1700000000.123:555):",
        ];

        let mut out: Vec<TraceEvent> = Vec::new();
        for l in lines {
            if let Some(mut evs) = acc.process_line(l, ns) {
                out.append(&mut evs);
            }
        }

        assert_eq!(out.len(), 1);
        let te = &out[0];
        assert!(matches!(te.kind, TraceEventKind::ProcExec));

        assert_eq!(te.actor.exe, None);
        assert_eq!(te.actor.comm, None);
        assert_eq!(te.actor.exe_hash, Some(hash_string_sha256("/bin/echo")));
        assert_eq!(te.actor.comm_hash, Some(hash_string_sha256("echo")));

        assert_eq!(te.attrs.argv, None);
        assert_eq!(te.attrs.cwd, None);
        assert_eq!(
            te.attrs.argv_hash,
            Some(hash_string_sha256("/bin/echo hello"))
        );
        assert_eq!(te.attrs.cwd_hash, Some(hash_string_sha256("/tmp")));
    }

    #[test]
    fn audit_assembler_proc_exec_raw() {
        let mut acc = AuditAccumulator::new_with_config("raw".to_string(), cfg_for_test());
        let ns = "ns://test";

        let lines = [
            "type=SYSCALL msg=audit(1700000000.123:777): arch=c000003e syscall=59 pid=123 ppid=1 uid=1000 gid=1000 auid=1000 ses=1 tty=\"pts0\" euid=1000 suid=1000 fsuid=1000 egid=1000 comm=\"echo\" exe=\"/bin/echo\"",
            "type=PROCTITLE msg=audit(1700000000.123:777): proctitle=2f62696e2f6563686f0068656c6c6f",
            "type=CWD msg=audit(1700000000.123:777): cwd=\"/tmp\"",
            "type=EOE msg=audit(1700000000.123:777):",
        ];

        let mut out: Vec<TraceEvent> = Vec::new();
        for l in lines {
            if let Some(mut evs) = acc.process_line(l, ns) {
                out.append(&mut evs);
            }
        }

        assert_eq!(out.len(), 1);
        let te = &out[0];
        assert!(matches!(te.kind, TraceEventKind::ProcExec));

        assert_eq!(te.actor.exe, Some("/bin/echo".to_string()));
        assert_eq!(te.actor.comm, Some("echo".to_string()));
        assert_eq!(te.actor.exe_hash, Some(hash_string_sha256("/bin/echo")));
        assert_eq!(te.actor.comm_hash, Some(hash_string_sha256("echo")));

        assert_eq!(te.attrs.argv, Some("/bin/echo hello".to_string()));
        assert_eq!(te.attrs.cwd, Some("/tmp".to_string()));
        assert_eq!(
            te.attrs.argv_hash,
            Some(hash_string_sha256("/bin/echo hello"))
        );
        assert_eq!(te.attrs.cwd_hash, Some(hash_string_sha256("/tmp")));
    }

    #[test]
    fn audit_assembler_file_open_hash_only() {
        let mut acc = AuditAccumulator::new_with_config("hash-only".to_string(), cfg_for_test());
        let ns = "ns://test";

        let lines = [
            "type=PATH msg=audit(1700000000.123:999): item=0 name=\"/etc/passwd\" inode=12345 nametype=CREATE objtype=CREATE",
            "type=SYSCALL msg=audit(1700000000.123:999): arch=c000003e syscall=2 pid=222 ppid=1 uid=1000 gid=1000",
            "type=EOE msg=audit(1700000000.123:999):",
        ];

        let mut out: Vec<TraceEvent> = Vec::new();
        for l in lines {
            if let Some(mut evs) = acc.process_line(l, ns) {
                out.append(&mut evs);
            }
        }

        assert_eq!(out.len(), 1);
        let te = &out[0];
        assert!(matches!(te.kind, TraceEventKind::FileOpen));

        assert_eq!(te.target.path, None);
        assert_eq!(te.target.path_hash, Some(hash_string_sha256("/etc/passwd")));
        assert_eq!(te.target.inode, Some(12345));
        assert_eq!(te.target.file_op, Some("create".to_string()));
    }

    #[test]
    fn audit_assembler_priv_change_syscall() {
        let mut acc = AuditAccumulator::new_with_config("hash-only".to_string(), cfg_for_test());
        let ns = "ns://test";

        let lines = [
            "type=SYSCALL msg=audit(1700000000.123:2001): arch=c000003e syscall=105 pid=333 ppid=1 uid=1000 gid=1000 auid=1000 ses=1 tty=\"pts0\" euid=0 suid=0 fsuid=0 egid=0",
            "type=EOE msg=audit(1700000000.123:2001):",
        ];

        let mut out: Vec<TraceEvent> = Vec::new();
        for l in lines {
            if let Some(mut evs) = acc.process_line(l, ns) {
                out.append(&mut evs);
            }
        }

        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].kind, TraceEventKind::PrivChange));
        assert_eq!(out[0].actor.pid, 333);
    }

    #[test]
    fn audit_assembler_priv_change_sudo_exec() {
        let mut acc = AuditAccumulator::new_with_config("hash-only".to_string(), cfg_for_test());
        let ns = "ns://test";

        let lines = [
            "type=SYSCALL msg=audit(1700000000.123:2002): arch=c000003e syscall=59 pid=444 ppid=1 uid=1000 gid=1000",
            "type=PROCTITLE msg=audit(1700000000.123:2002): proctitle=2f7573722f62696e2f7375646f006964",
            "type=EOE msg=audit(1700000000.123:2002):",
        ];

        let mut out: Vec<TraceEvent> = Vec::new();
        for l in lines {
            if let Some(mut evs) = acc.process_line(l, ns) {
                out.append(&mut evs);
            }
        }

        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].kind, TraceEventKind::PrivChange));
        assert_eq!(out[0].attrs.argv, None);
        assert_eq!(
            out[0].attrs.argv_hash,
            Some(hash_string_sha256("/usr/bin/sudo id"))
        );
    }

    #[test]
    fn audit_assembler_file_open_raw() {
        let mut acc = AuditAccumulator::new_with_config("raw".to_string(), cfg_for_test());
        let ns = "ns://test";

        let lines = [
            "type=PATH msg=audit(1700000000.123:1001): item=0 name=\"/etc/passwd\" inode=12345 nametype=CREATE objtype=CREATE",
            "type=SYSCALL msg=audit(1700000000.123:1001): arch=c000003e syscall=2 pid=222 ppid=1 uid=1000 gid=1000",
            "type=EOE msg=audit(1700000000.123:1001):",
        ];

        let mut out: Vec<TraceEvent> = Vec::new();
        for l in lines {
            if let Some(mut evs) = acc.process_line(l, ns) {
                out.append(&mut evs);
            }
        }

        assert_eq!(out.len(), 1);
        let te = &out[0];
        assert!(matches!(te.kind, TraceEventKind::FileOpen));

        assert_eq!(te.target.path, Some("/etc/passwd".to_string()));
        assert_eq!(te.target.path_hash, Some(hash_string_sha256("/etc/passwd")));
        assert_eq!(te.target.inode, Some(12345));
        assert_eq!(te.target.file_op, Some("create".to_string()));
    }

    #[test]
    fn proc_net_helpers_privacy_and_protocol_and_state() {
        assert_eq!(protocol_from_table("tcp"), Some("tcp".to_string()));
        assert_eq!(protocol_from_table("tcp6"), Some("tcp".to_string()));
        assert_eq!(protocol_from_table("udp"), Some("udp".to_string()));
        assert_eq!(protocol_from_table("udp6"), Some("udp".to_string()));
        assert_eq!(protocol_from_table("weird"), None);

        assert_eq!(src_from_privacy_mode("hash-only", "1.2.3.4:123"), None);
        assert_eq!(
            src_from_privacy_mode("raw", "1.2.3.4:123"),
            Some("1.2.3.4:123".to_string())
        );

        assert_eq!(
            state_from_table("tcp", Some("01")),
            Some("ESTABLISHED".to_string())
        );
        assert_eq!(
            state_from_table("tcp6", Some("0A")),
            Some("LISTEN".to_string())
        );
        assert_eq!(state_from_table("udp", Some("01")), None);
        assert_eq!(state_from_table("udp6", Some("01")), None);

        assert_eq!(
            parse_tx_rx_queues(Some("00000010:00000020")),
            (Some(16), Some(32))
        );
        assert_eq!(
            parse_tx_rx_queues(Some("00000000:00000000")),
            (Some(0), Some(0))
        );
        assert_eq!(parse_tx_rx_queues(None), (None, None));
    }
}
