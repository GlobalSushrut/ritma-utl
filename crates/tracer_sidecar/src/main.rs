use std::collections::HashSet;
use std::fs::{metadata, read_to_string, File};
use std::io::{Read, Seek};
use std::thread::{sleep, spawn};
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use chrono::Utc;
use common_models::hash_string_sha256;
use common_models::{
    TraceActor, TraceAttrs, TraceEvent, TraceEventKind, TraceSourceKind, TraceTarget,
};
use index_db::IndexDb;

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
        let tcp_path = format!("{proc_root}/net/tcp");
        if let Ok(s) = read_to_string(&tcp_path) {
            for (i, line) in s.lines().enumerate() {
                if i == 0 {
                    continue;
                }
                // fields: sl local_address rem_address st ...
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() > 3 {
                    if let Some(dst) = hex_to_ipv4_port(cols[2]) {
                        if seen.insert(dst.clone()) {
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
                                    pid: 0,
                                    ppid: 0,
                                    uid: 0,
                                    gid: 0,
                                    container_id: None,
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
    let audit_path =
        std::env::var("AUDIT_LOG_PATH").unwrap_or_else(|_| "/var/log/audit/audit.log".to_string());
    let index_path =
        std::env::var("INDEX_DB_PATH").unwrap_or_else(|_| "/data/index_db.sqlite".to_string());
    let proc_root = std::env::var("PROC_ROOT").unwrap_or_else(|_| "/proc".to_string());
    let net_scan_secs: u64 = std::env::var("NET_SCAN_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

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

    // Keep main alive
    loop {
        sleep(Duration::from_secs(3600));
    }
}
