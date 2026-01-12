use std::collections::{HashMap, HashSet};
use std::fs::{metadata, read_dir, read_link, read_to_string, File};
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::thread::{sleep, spawn};
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use chrono::Utc;
use common_models::hash_string_sha256;
use common_models::{
    TraceActor, TraceAttrs, TraceEvent, TraceEventKind, TraceSourceKind, TraceTarget,
};
use ebpf_provider::{EbpfProvider, TraceProviderSelector};
use index_db::IndexDb;
use ritma_contract::{ResolveOpts, StorageContract};

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
        .map_err(|e| std::io::Error::other(e))?;

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

    Some(ProcMetaFull {
        pid,
        ppid,
        uid,
        gid,
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
        let Ok(pid) = pid_s.parse::<i64>() else { continue };
        let Some(meta) = proc_meta(proc_root, pid) else { continue };

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
                    let Some(dst) = parse_addr(cols[2]) else {
                        continue;
                    };
                    let inode = cols[9].parse::<u64>().ok();
                    let meta = inode.and_then(|ino| inode_map.get(&ino).cloned());

                    let (pid, ppid, uid, gid, comm_hash, exe_hash, comm, exe, container_id) =
                        if let Some(m) = meta {
                            (
                                m.pid,
                                m.ppid,
                                m.uid,
                                m.gid,
                                m.comm_hash.clone(),
                                m.exe_hash.clone(),
                                m.comm.clone(),
                                m.exe.clone(),
                                m.container_id.clone(),
                            )
                    } else {
                            (0, 0, 0, 0, None, None, None, None, None)
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
                        },
                        attrs: TraceAttrs {
                            argv_hash: None,
                            cwd_hash: None,
                            bytes_out: None,
                        },
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

    // Defaults
    let mut actor = TraceActor {
        pid: 0,
        ppid: 0,
        uid: 0,
        gid: 0,
        comm_hash: None,
        exe_hash: None,
        comm: None,
        exe: None,
        container_id: None,
        service: None,
        build_hash: None,
    };
    if let Some(pid_s) = parse_token(line, " pid=") {
        actor.pid = pid_s.parse().unwrap_or(0);
    }
    if let Some(uid_s) = parse_token(line, " uid=") {
        actor.uid = uid_s.parse().unwrap_or(0);
    }
    if let Some(gid_s) = parse_token(line, " gid=") {
        actor.gid = gid_s.parse().unwrap_or(0);
    }

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
            },
            attrs: TraceAttrs {
                argv_hash: None,
                cwd_hash: None,
                bytes_out: None,
            },
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
            },
            attrs: TraceAttrs {
                argv_hash,
                cwd_hash: None,
                bytes_out: None,
            },
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
            },
            attrs: TraceAttrs {
                argv_hash: None,
                cwd_hash: None,
                bytes_out: None,
            },
        };
        return Some(te);
    }

    None
}

fn tail_file_to_indexdb(index: &IndexDb, path: &str, namespace_id: &str) -> Result<()> {
    let mut offset: u64 = 0;
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
                    if let Some(te) = map_line_to_trace(line, namespace_id) {
                        let _ = index.insert_trace_event_from_model(&te);
                    }
                }
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
    validate_path_str("AUDIT_LOG_PATH", &audit_path, false)
        .map_err(std::io::Error::other)?;

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
