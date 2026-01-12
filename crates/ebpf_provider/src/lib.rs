use anyhow::Result;
use common_models::TraceEvent;

#[cfg(feature = "aya")]
use common_models::{TraceActor, TraceAttrs, TraceEventKind, TraceSourceKind, TraceTarget};

#[cfg(feature = "aya")]
use index_db::IndexDb;

#[cfg(feature = "aya")]
use std::path::Path;
#[cfg(feature = "aya")]
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

/// eBPF Provider using Aya
/// This is a stub implementation - full eBPF requires:
/// 1. eBPF programs written in Rust (separate crate)
/// 2. CAP_BPF capability
/// 3. BPF filesystem mounted
/// 4. Kernel >= 5.8
pub struct EbpfProvider {
    namespace_id: String,
    index_db_path: String,
    #[cfg(feature = "aya")]
    stop_flag: Option<Arc<AtomicBool>>,
    #[cfg(feature = "aya")]
    worker: Option<std::thread::JoinHandle<()>>,
}

impl EbpfProvider {
    pub fn new(namespace_id: String, index_db_path: String) -> Self {
        Self {
            namespace_id,
            index_db_path,
            #[cfg(feature = "aya")]
            stop_flag: None,
            #[cfg(feature = "aya")]
            worker: None,
        }
    }

    /// Check if eBPF is available
    pub fn is_available() -> bool {
        // Check for BPF FS
        std::path::Path::new("/sys/fs/bpf").exists()
    }

    /// Start eBPF tracing
    /// Full implementation would:
    /// 1. Load eBPF programs for execve, connect, open, dns
    /// 2. Attach to kprobes/tracepoints
    /// 3. Read from perf/ring buffers
    /// 4. Map cgroup to container ID
    #[cfg(not(feature = "aya"))]
    pub fn start(&mut self) -> Result<()> {
        log::warn!(
            "ebpf_provider inactive (built without feature 'aya'): namespace={} index_db_path={}",
            self.namespace_id,
            self.index_db_path
        );
        Ok(())
    }

    #[cfg(feature = "aya")]
    pub fn start(&mut self) -> Result<()> {
        use bytemuck::{Pod, Zeroable};
        use std::collections::HashMap;
        use std::fs::read_to_string;
        use std::time::{Duration, Instant};

        const RITMA_EVENT_EXECVE: u32 = 1;
        const RITMA_EVENT_OPENAT: u32 = 2;
        const RITMA_EVENT_CONNECT: u32 = 3;
        const RITMA_EVENT_DNS: u32 = 4;

        // Must match deploy/ebpf/ritma_trace.c `struct ritma_event` layout.
        // We represent the union as a fixed payload.
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Zeroable, Pod)]
        struct RitmaEvent {
            kind: u32,
            pid: u32,
            ppid: u32,
            uid: u32,
            gid: u32,
            _pad: u32,
            cgroup_id: u64,
            data: [u8; 128],
        }

        if !Self::is_available() {
            anyhow::bail!("eBPF not available - /sys/fs/bpf not found");
        }

        log::info!(
            "eBPF provider starting for namespace: {}",
            self.namespace_id
        );

        let obj_path = std::env::var("RITMA_EBPF_OBJECT_PATH").unwrap_or_default();
        if obj_path.is_empty() {
            log::warn!("RITMA_EBPF_OBJECT_PATH not set; eBPF provider inactive");
            return Ok(());
        }
        if !Path::new(&obj_path).exists() {
            anyhow::bail!("RITMA_EBPF_OBJECT_PATH does not exist: {obj_path}");
        }

        let privacy_mode = std::env::var("PRIVACY_MODE").unwrap_or_else(|_| "hash-only".to_string());
        let proc_root = std::env::var("PROC_ROOT").unwrap_or_else(|_| "/proc".to_string());

        let mut bpf = aya::Bpf::load_file(&obj_path)?;

        let attach_tp = |bpf: &mut aya::Bpf, prog_name: &str, tp: &str| -> Result<bool> {
            let program: &mut aya::programs::TracePoint = match bpf.program_mut(prog_name) {
                Some(p) => p.try_into()?,
                None => {
                    eprintln!("ebpf_provider: eBPF program not found in object: {prog_name}");
                    return Ok(false);
                }
            };
            program.load()?;
            program.attach("syscalls", tp)?;
            Ok(true)
        };

        let hooks: [(&str, &str); 5] = [
            ("ritma_execve", "sys_enter_execve"),
            ("ritma_openat", "sys_enter_openat"),
            ("ritma_connect", "sys_enter_connect"),
            ("ritma_sendto", "sys_enter_sendto"),
            ("ritma_sendmsg", "sys_enter_sendmsg"),
        ];

        let mode = std::env::var("RITMA_MODE").unwrap_or_else(|_| "observe".to_string());
        let strict = std::env::var("RITMA_EBPF_STRICT")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(mode == "forensic");

        let mut attached = 0usize;
        let mut attached_by_prog: HashMap<&'static str, bool> = HashMap::new();
        for (prog, tp) in hooks {
            let ok = match attach_tp(&mut bpf, prog, tp) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ebpf_provider: attach failed: prog={prog} tp={tp} err={e}");
                    false
                }
            };
            attached_by_prog.insert(prog, ok);
            if ok {
                attached += 1;
            }
        }

        eprintln!(
            "ebpf_provider: attach summary: {attached}/{} execve={} openat={} connect={} sendto={} sendmsg={}",
            hooks.len(),
            attached_by_prog.get("ritma_execve").copied().unwrap_or(false),
            attached_by_prog.get("ritma_openat").copied().unwrap_or(false),
            attached_by_prog.get("ritma_connect").copied().unwrap_or(false),
            attached_by_prog.get("ritma_sendto").copied().unwrap_or(false),
            attached_by_prog.get("ritma_sendmsg").copied().unwrap_or(false)
        );

        if attached == 0 {
            anyhow::bail!(
                "no eBPF tracepoints attached; check kernel support, CAP_BPF/CAP_SYS_ADMIN, and verifier logs"
            );
        }

        if strict {
            let mut missing: Vec<&str> = ["ritma_execve", "ritma_openat", "ritma_connect"]
                .into_iter()
                .filter(|p| !attached_by_prog.get(p).copied().unwrap_or(false))
                .collect();
            let dns_ok = attached_by_prog
                .get("ritma_sendto")
                .copied()
                .unwrap_or(false)
                || attached_by_prog
                    .get("ritma_sendmsg")
                    .copied()
                    .unwrap_or(false);
            if !dns_ok {
                missing.push("ritma_sendto|ritma_sendmsg");
            }
            if !missing.is_empty() {
                anyhow::bail!(
                    "RITMA_EBPF_STRICT=1 and some hooks failed to attach: {}",
                    missing.join(",")
                );
            }
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag2 = stop_flag.clone();
        self.stop_flag = Some(stop_flag);

        let namespace_id = self.namespace_id.clone();
        let index_db_path = self.index_db_path.clone();
        let proc_root = proc_root.clone();

        let worker = std::thread::spawn(move || {
            fn parse_dns_qname(payload: &[u8]) -> Option<String> {
                if payload.len() < 13 {
                    return None;
                }
                let mut i = 12usize;
                let mut labels: Vec<String> = Vec::new();
                while i < payload.len() {
                    let len = payload[i] as usize;
                    i += 1;
                    if len == 0 {
                        break;
                    }
                    if (len & 0xC0) != 0 {
                        return None;
                    }
                    if len > 63 {
                        return None;
                    }
                    if i + len > payload.len() {
                        return None;
                    }
                    let part = String::from_utf8_lossy(&payload[i..i + len]).to_string();
                    labels.push(part);
                    i += len;
                    if labels.len() > 32 {
                        break;
                    }
                }
                if labels.is_empty() {
                    return None;
                }
                let name = labels.join(".");
                if name.len() > 253 {
                    return None;
                }
                Some(name)
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

            let debug_sample_n: u64 = std::env::var("RITMA_DEBUG_SAMPLE_EBPF_N")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let mut debug_counter: u64 = 0;

            fn proc_ppid(proc_root: &str, pid: i64) -> Option<i64> {
                let status = read_to_string(format!("{proc_root}/{pid}/status")).ok()?;
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("PPid:") {
                        return rest.split_whitespace().next()?.parse::<i64>().ok();
                    }
                }
                None
            }

            fn proc_container_id(proc_root: &str, pid: i64) -> Option<String> {
                let cgroup = read_to_string(format!("{proc_root}/{pid}/cgroup")).ok()?;
                find_hex64(&cgroup)
            }

            let map = match bpf.map_mut("events") {
                Some(m) => m,
                None => {
                    eprintln!("ebpf_provider: missing ringbuf map: events");
                    return;
                }
            };

            let mut ring = match aya::maps::RingBuf::try_from(map) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("ebpf_provider: ringbuf init failed: {e}");
                    return;
                }
            };

            struct ProcMeta {
                t: Instant,
                ppid: i64,
                container_id: Option<String>,
                comm: Option<String>,
                exe: Option<String>,
                comm_hash: Option<String>,
                exe_hash: Option<String>,
            }

            let mut cache: HashMap<i64, ProcMeta> = HashMap::new();
            let cache_ttl = Duration::from_secs(30);

            let default_fileopen_ignore_prefixes = if mode == "investigate" || mode == "forensic" {
                "/proc,/sys,/dev,/run,/var/lib/docker,/snap".to_string()
            } else {
                "/proc,/sys,/dev,/run,/var/lib/docker,/snap,/tmp,/var/tmp,/lib,/usr/lib,/usr/share".to_string()
            };
            let fileopen_ignore_prefixes = std::env::var("RITMA_FILEOPEN_IGNORE_PREFIXES")
                .unwrap_or(default_fileopen_ignore_prefixes);
            let fileopen_ignore_prefixes: Vec<String> = fileopen_ignore_prefixes
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let default_fileopen_max_per_pid_per_sec: u32 = if mode == "forensic" {
                50
            } else if mode == "investigate" {
                20
            } else {
                10
            };
            let fileopen_max_per_pid_per_sec: u32 = std::env::var("RITMA_FILEOPEN_MAX_PER_PID_PER_SEC")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(default_fileopen_max_per_pid_per_sec);

            let default_fileopen_dedup_window_ms: u64 = if mode == "forensic" { 0 } else { 2000 };
            let fileopen_dedup_window_ms: u64 = std::env::var("RITMA_FILEOPEN_DEDUP_WINDOW_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(default_fileopen_dedup_window_ms);

            let mut fileopen_rate: HashMap<i64, (Instant, u32)> = HashMap::new();
            let mut fileopen_dedup: HashMap<(i64, u64), Instant> = HashMap::new();

            // Open DB once; retry until available (or stop).
            let db = loop {
                if stop_flag2.load(Ordering::Relaxed) {
                    return;
                }
                match IndexDb::open(&index_db_path) {
                    Ok(db) => break db,
                    Err(e) => {
                        eprintln!("ebpf_provider: open index db failed: {e}");
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            };

            while !stop_flag2.load(Ordering::Relaxed) {
                let mut did_work = false;
                while let Some(item) = ring.next() {
                    did_work = true;
                    if item.len() < std::mem::size_of::<RitmaEvent>() {
                        continue;
                    }
                    let ev = match bytemuck::try_from_bytes::<RitmaEvent>(&item) {
                        Ok(ev) => *ev,
                        Err(_) => continue,
                    };

                    let pid = ev.pid as i64;
                    let now = Instant::now();

                    let meta = match cache.get(&pid) {
                        Some(m) if now.duration_since(m.t) <= cache_ttl => ProcMeta {
                            t: m.t,
                            ppid: m.ppid,
                            container_id: m.container_id.clone(),
                            comm: m.comm.clone(),
                            exe: m.exe.clone(),
                            comm_hash: m.comm_hash.clone(),
                            exe_hash: m.exe_hash.clone(),
                        },
                        _ => {
                            let ppid = proc_ppid(&proc_root, pid).unwrap_or(ev.ppid as i64);
                            let cid = proc_container_id(&proc_root, pid);

                            let comm = read_to_string(format!("{proc_root}/{pid}/comm"))
                                .ok()
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty());
                            let exe = std::fs::read_link(format!("{proc_root}/{pid}/exe"))
                                .ok()
                                .and_then(|p| p.to_str().map(|s| s.to_string()))
                                .filter(|s| !s.is_empty());

                            let comm_hash = comm.as_ref().map(|s| common_models::hash_string_sha256(s));
                            let exe_hash = exe.as_ref().map(|s| common_models::hash_string_sha256(s));

                            let m = ProcMeta {
                                t: now,
                                ppid,
                                container_id: cid,
                                comm,
                                exe,
                                comm_hash,
                                exe_hash,
                            };
                            cache.insert(pid, ProcMeta {
                                t: m.t,
                                ppid: m.ppid,
                                container_id: m.container_id.clone(),
                                comm: m.comm.clone(),
                                exe: m.exe.clone(),
                                comm_hash: m.comm_hash.clone(),
                                exe_hash: m.exe_hash.clone(),
                            });
                            m
                        }
                    };

                    let (comm_raw, exe_raw) = if privacy_mode == "raw" {
                        (meta.comm.clone(), meta.exe.clone())
                    } else {
                        (None, None)
                    };

                    let actor = TraceActor {
                        pid,
                        ppid: meta.ppid,
                        uid: ev.uid as i64,
                        gid: ev.gid as i64,
                        comm_hash: meta.comm_hash.clone(),
                        exe_hash: meta.exe_hash.clone(),
                        comm: comm_raw,
                        exe: exe_raw,
                        container_id: meta
                            .container_id
                            .clone()
                            .or_else(|| Some(format!("cgroup:{:x}", ev.cgroup_id))),
                        service: None,
                        build_hash: None,
                    };

                    if debug_sample_n > 0 {
                        debug_counter = debug_counter.wrapping_add(1);
                        if debug_counter % debug_sample_n == 0 {
                            eprintln!(
                                "ebpf_provider: sample kind={} pid={} comm_hash={:?} exe_hash={:?} comm={:?} exe={:?}",
                                ev.kind,
                                actor.pid,
                                actor.comm_hash,
                                actor.exe_hash,
                                actor.comm,
                                actor.exe
                            );
                        }
                    }

                    match ev.kind {
                        RITMA_EVENT_EXECVE => {
                            let te = TraceEvent {
                                trace_id: format!("te_{}", uuid::Uuid::new_v4()),
                                ts: chrono::Utc::now().to_rfc3339(),
                                namespace_id: namespace_id.clone(),
                                source: TraceSourceKind::Ebpf,
                                kind: TraceEventKind::ProcExec,
                                actor,
                                target: TraceTarget {
                                    path_hash: None,
                                    dst: None,
                                    domain_hash: None,
                                },
                                attrs: TraceAttrs {
                                    argv_hash: None,
                                    cwd_hash: None,
                                    bytes_out: None,
                                },
                            };
                            let _ = db.insert_trace_event_from_model(&te);
                        }
                        RITMA_EVENT_OPENAT => {
                            let path_bytes = &ev.data;
                            let end = path_bytes
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(path_bytes.len());
                            let path = String::from_utf8_lossy(&path_bytes[..end]).to_string();

                            if fileopen_ignore_prefixes
                                .iter()
                                .any(|p| path.starts_with(p))
                            {
                                continue;
                            }

                            let now = Instant::now();
                            if fileopen_max_per_pid_per_sec > 0 {
                                match fileopen_rate.get_mut(&pid) {
                                    Some((start, count)) if now.duration_since(*start) < Duration::from_secs(1) => {
                                        if *count >= fileopen_max_per_pid_per_sec {
                                            continue;
                                        }
                                        *count += 1;
                                    }
                                    Some((start, count)) => {
                                        *start = now;
                                        *count = 1;
                                    }
                                    None => {
                                        fileopen_rate.insert(pid, (now, 1));
                                    }
                                }
                            }

                            let path_hash = common_models::hash_string_sha256(&path);
                            let key_hash64 = u64::from_str_radix(&path_hash[..16], 16).unwrap_or(0);
                            let dedup_key = (pid, key_hash64);
                            if fileopen_dedup_window_ms > 0 {
                                if let Some(last) = fileopen_dedup.get(&dedup_key) {
                                    if now.duration_since(*last)
                                        < Duration::from_millis(fileopen_dedup_window_ms)
                                    {
                                        continue;
                                    }
                                }
                                fileopen_dedup.insert(dedup_key, now);
                            }

                            let te = TraceEvent {
                                trace_id: format!("te_{}", uuid::Uuid::new_v4()),
                                ts: chrono::Utc::now().to_rfc3339(),
                                namespace_id: namespace_id.clone(),
                                source: TraceSourceKind::Ebpf,
                                kind: TraceEventKind::FileOpen,
                                actor,
                                target: TraceTarget {
                                    path_hash: Some(path_hash),
                                    dst: None,
                                    domain_hash: None,
                                },
                                attrs: TraceAttrs {
                                    argv_hash: None,
                                    cwd_hash: None,
                                    bytes_out: None,
                                },
                            };
                            let _ = db.insert_trace_event_from_model(&te);
                        }
                        RITMA_EVENT_CONNECT => {
                            if ev.data.len() < 20 {
                                continue;
                            }
                            let family = u16::from_ne_bytes([ev.data[0], ev.data[1]]);
                            let dport = u16::from_ne_bytes([ev.data[2], ev.data[3]]);
                            let daddr = &ev.data[4..20];

                            let dst = if family as i32 == libc::AF_INET {
                                // C side copies sin_addr.s_addr (u32) by bytes, which on little-endian
                                // yields reversed bytes. Normalize back to network order.
                                let v = u32::from_le_bytes([daddr[0], daddr[1], daddr[2], daddr[3]]);
                                let ip = std::net::Ipv4Addr::from(v);
                                format!("{ip}:{dport}")
                            } else if family as i32 == libc::AF_INET6 {
                                let mut bytes = [0u8; 16];
                                bytes.copy_from_slice(daddr);
                                let addr = std::net::Ipv6Addr::from(bytes);
                                format!("[{addr}]:{dport}")
                            } else {
                                format!("family={family}:::{dport}")
                            };

                            let (dst_opt, domain_hash_opt) = if privacy_mode == "raw" {
                                (Some(dst.clone()), Some(common_models::hash_string_sha256(&dst)))
                            } else {
                                (None, Some(common_models::hash_string_sha256(&dst)))
                            };

                            let te = TraceEvent {
                                trace_id: format!("te_{}", uuid::Uuid::new_v4()),
                                ts: chrono::Utc::now().to_rfc3339(),
                                namespace_id: namespace_id.clone(),
                                source: TraceSourceKind::Ebpf,
                                kind: TraceEventKind::NetConnect,
                                actor,
                                target: TraceTarget {
                                    path_hash: None,
                                    dst: dst_opt,
                                    domain_hash: domain_hash_opt,
                                },
                                attrs: TraceAttrs {
                                    argv_hash: None,
                                    cwd_hash: None,
                                    bytes_out: None,
                                },
                            };
                            let _ = db.insert_trace_event_from_model(&te);
                        }
                        RITMA_EVENT_DNS => {
                            if ev.data.len() < 24 {
                                continue;
                            }
                            let family = u16::from_ne_bytes([ev.data[0], ev.data[1]]);
                            let dport = u16::from_ne_bytes([ev.data[2], ev.data[3]]);
                            let daddr = &ev.data[4..20];
                            let len = u32::from_ne_bytes([ev.data[20], ev.data[21], ev.data[22], ev.data[23]]) as usize;

                            let max_payload = 96usize;
                            let cap = std::cmp::min(len, max_payload);
                            let payload = &ev.data[24..24 + cap];

                            let server = if family as i32 == libc::AF_INET {
                                let v = u32::from_le_bytes([daddr[0], daddr[1], daddr[2], daddr[3]]);
                                let ip = std::net::Ipv4Addr::from(v);
                                format!("{ip}:{dport}")
                            } else if family as i32 == libc::AF_INET6 {
                                let mut bytes = [0u8; 16];
                                bytes.copy_from_slice(daddr);
                                let addr = std::net::Ipv6Addr::from(bytes);
                                format!("[{addr}]:{dport}")
                            } else {
                                format!("family={family}:::{dport}")
                            };

                            let (qname_opt, domain_hash) = match parse_dns_qname(payload) {
                                Some(qname) => {
                                    let h = common_models::hash_string_sha256(&qname);
                                    (Some(qname), Some(h))
                                }
                                None => {
                                    let payload_hex = hex::encode(payload);
                                    let h = common_models::hash_string_sha256(&payload_hex);
                                    (None, Some(h))
                                }
                            };

                            let dst_opt = if privacy_mode == "raw" {
                                match qname_opt {
                                    Some(q) => Some(format!("{q}@{server}")),
                                    None => Some(format!("dns@{server}")),
                                }
                            } else {
                                None
                            };

                            let te = TraceEvent {
                                trace_id: format!("te_{}", uuid::Uuid::new_v4()),
                                ts: chrono::Utc::now().to_rfc3339(),
                                namespace_id: namespace_id.clone(),
                                source: TraceSourceKind::Ebpf,
                                kind: TraceEventKind::DnsQuery,
                                actor,
                                target: TraceTarget {
                                    path_hash: None,
                                    dst: dst_opt,
                                    domain_hash,
                                },
                                attrs: TraceAttrs {
                                    argv_hash: None,
                                    cwd_hash: None,
                                    bytes_out: Some(cap as i64),
                                },
                            };
                            let _ = db.insert_trace_event_from_model(&te);
                        }
                        _ => {}
                    }
                }

                if !did_work {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        });

        self.worker = Some(worker);
        log::info!("eBPF provider active (tracepoint + ringbuf ingestion)");
        Ok(())
    }

    /// Stop eBPF tracing
    #[cfg(not(feature = "aya"))]
    pub fn stop(&mut self) -> Result<()> {
        Ok(())
    }

    #[cfg(feature = "aya")]
    pub fn stop(&mut self) -> Result<()> {
        log::info!("eBPF provider stopping");
        if let Some(flag) = self.stop_flag.take() {
            flag.store(true, Ordering::Relaxed);
        }
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
        Ok(())
    }
}

/// Trait for trace providers
pub trait TracerProvider {
    fn start(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn emit(&self, event: TraceEvent) -> Result<()>;
}

/// Provider abstraction that selects best available provider
pub struct TraceProviderSelector;

impl TraceProviderSelector {
    pub fn select_best() -> &'static str {
        if cfg!(feature = "aya")
            && EbpfProvider::is_available()
            && std::env::var("RITMA_EBPF_OBJECT_PATH")
                .ok()
                .filter(|p| !p.is_empty() && std::path::Path::new(p).exists())
                .is_some()
        {
            "ebpf"
        } else if std::path::Path::new("/var/log/audit/audit.log").exists() {
            "auditd"
        } else {
            "runtime"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_selection() {
        let provider = TraceProviderSelector::select_best();
        assert!(provider == "ebpf" || provider == "auditd" || provider == "runtime");
    }
}
