#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ritma-ebpf-helper is only supported on linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;

    use security_os::Did;

    let mut args = env::args().skip(1);
    let src_did = args.next().ok_or("missing src_did")?;
    let dst_did = args.next().ok_or("missing dst_did")?;
    let decision = args
        .next()
        .ok_or("missing decision (allow|deny|throttle|isolate)")?;

    // Basic validation of DIDs; errors here mean upstream misconfiguration.
    let _ = Did::parse(&src_did).map_err(|e| format!("invalid src_did {src_did}: {e}"))?;
    let _ = Did::parse(&dst_did).map_err(|e| format!("invalid dst_did {dst_did}: {e}"))?;

    let map_path = env::var("RITMA_EBPF_MAP_PATH")
        .unwrap_or_else(|_| "/sys/fs/bpf/ritma_fw_pairs".to_string());
    let mode = env::var("RITMA_EBPF_MODE").unwrap_or_else(|_| "log".to_string());

    match mode.as_str() {
        "log" => backend_log(&map_path, &src_did, &dst_did, &decision),
        "bpf" => backend_bpf(&map_path, &src_did, &dst_did, &decision),
        other => {
            eprintln!("[ebpf-helper] unknown RITMA_EBPF_MODE={other}, falling back to log");
            backend_log(&map_path, &src_did, &dst_did, &decision)
        }
    }
}

#[cfg(target_os = "linux")]
fn backend_log(
    map_path: &str,
    src_did: &str,
    dst_did: &str,
    decision: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (action, note) = match decision {
        "deny" | "isolate" => ("update", "mark pair as denied/isolated"),
        "allow" => ("delete", "remove any deny/isolated mark for pair"),
        "throttle" => ("update", "throttle semantics TBD"),
        other => ("noop", other),
    };

    println!(
        "[ebpf-helper] mode=log map_path={map_path} src_did={src_did} dst_did={dst_did} decision={decision} action={action} note={note}"
    );

    Ok(())
}

#[cfg(target_os = "linux")]
fn backend_bpf(
    map_path: &str,
    src_did: &str,
    dst_did: &str,
    decision: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Map DIDs to u32 IDs using a simple hash.
    // In production, you'd maintain a persistent DID→ID registry.
    fn did_to_id(did: &str) -> u32 {
        let mut hasher = DefaultHasher::new();
        did.hash(&mut hasher);
        (hasher.finish() & 0xFFFFFFFF) as u32
    }

    let src_id = did_to_id(src_did);
    let dst_id = did_to_id(dst_did);

    // BPF map key: struct { u32 src_id; u32 dst_id; }
    // BPF map value: u8 (0=allow, 1=deny, 2=throttle, 3=isolate)
    let key_hex = format!("{src_id:08x}{dst_id:08x}");

    match decision {
        "deny" => {
            // Update map: key → value=1 (deny)
            let value_hex = "01"; // deny
            println!(
                "[ebpf-helper] mode=bpf map={map_path} key={key_hex} value={value_hex} action=update (deny)"
            );
            bpftool_map_update(map_path, &key_hex, value_hex)?;
        }
        "isolate" => {
            // Update map: key → value=3 (isolate)
            let value_hex = "03"; // isolate
            println!(
                "[ebpf-helper] mode=bpf map={map_path} key={key_hex} value={value_hex} action=update (isolate)"
            );
            bpftool_map_update(map_path, &key_hex, value_hex)?;
        }
        "allow" => {
            // Delete map entry to allow traffic (deny-list model)
            println!("[ebpf-helper] mode=bpf map={map_path} key={key_hex} action=delete (allow)");
            bpftool_map_delete(map_path, &key_hex)?;
        }
        "throttle" => {
            // Update map: key → value=2 (throttle)
            let value_hex = "02"; // throttle
            println!(
                "[ebpf-helper] mode=bpf map={map_path} key={key_hex} value={value_hex} action=update (throttle)"
            );
            bpftool_map_update(map_path, &key_hex, value_hex)?;
        }
        other => {
            eprintln!("[ebpf-helper] unknown decision: {other}");
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn bpftool_map_update(
    map_path: &str,
    key_hex: &str,
    value_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let status = Command::new("bpftool")
        .args([
            "map", "update", "pinned", map_path, "key", "hex", key_hex, "value", "hex", value_hex,
        ])
        .status()?;

    if !status.success() {
        return Err(format!("bpftool map update failed: {:?}", status.code()).into());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn bpftool_map_delete(map_path: &str, key_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let status = Command::new("bpftool")
        .args(["map", "delete", "pinned", map_path, "key", "hex", key_hex])
        .status()?;

    // Ignore errors if key doesn't exist (idempotent delete)
    if !status.success() {
        eprintln!(
            "[ebpf-helper] bpftool map delete warning: {:?} (key may not exist)",
            status.code()
        );
    }

    Ok(())
}
