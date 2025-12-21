#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ritma-firewall-helper is only supported on linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use security_os::Did;

    let mut args = env::args().skip(1);
    let src_did = args.next().ok_or("missing src_did")?;
    let dst_did = args.next().ok_or("missing dst_did")?;
    let decision = args.next().ok_or("missing decision (allow|deny|throttle|isolate)")?;

    // Basic validation of DIDs; errors here mean upstream misconfiguration.
    let _ = Did::parse(&src_did).map_err(|e| format!("invalid src_did {}: {}", src_did, e))?;
    let _ = Did::parse(&dst_did).map_err(|e| format!("invalid dst_did {}: {}", dst_did, e))?;

    let backend = env::var("RITMA_FW_BACKEND").unwrap_or_else(|_| "log".to_string());

    match backend.as_str() {
        "log" => backend_log(&src_did, &dst_did, &decision),
        "nft" => backend_nft(&src_did, &dst_did, &decision),
        "ebpf" => backend_ebpf(&src_did, &dst_did, &decision),
        other => {
            eprintln!("unknown RITMA_FW_BACKEND={}, falling back to log", other);
            backend_log(&src_did, &dst_did, &decision)
        }
    }
}

#[cfg(target_os = "linux")]
fn backend_log(src_did: &str, dst_did: &str, decision: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "[fw-helper] backend=log src_did={} dst_did={} decision={}",
        src_did, dst_did, decision
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_nft_table_and_chain(table: &str, chain: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Check for table; if missing, create it.
    let status = Command::new("nft").args(["list", "table", table]).status()?;
    if !status.success() {
        println!("[fw-helper] backend=nft creating table {}", table);
        let status = Command::new("nft").args(["add", "table", table]).status()?;
        if !status.success() {
            return Err(format!("failed to create nft table {}: {:?}", table, status.code()).into());
        }
    }

    // Check for chain; if missing, create a simple filter chain.
    let status = Command::new("nft").args(["list", "chain", table, chain]).status()?;
    if !status.success() {
        println!("[fw-helper] backend=nft creating chain {} {}", table, chain);
        let status = Command::new("nft").args([
            "add", "chain",
            table,
            chain,
            "{", "type", "filter", "hook", "forward", "priority", "0", ";", "}",
        ]).status()?;
        if !status.success() {
            return Err(format!("failed to create nft chain {} {}: {:?}", table, chain, status.code()).into());
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn backend_ebpf(src_did: &str, dst_did: &str, decision: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    let helper = env::var("RITMA_FW_EBPF_HELPER").unwrap_or_else(|_| "".to_string());
    if helper.is_empty() {
        println!(
            "[fw-helper] backend=ebpf src_did={} dst_did={} decision={} (no helper configured)",
            src_did, dst_did, decision
        );
        return Ok(());
    }

    println!(
        "[fw-helper] backend=ebpf helper={} src_did={} dst_did={} decision={}",
        helper, src_did, dst_did, decision
    );

    let status = Command::new(&helper)
        .arg(src_did)
        .arg(dst_did)
        .arg(decision)
        .status()?;
    if !status.success() {
        return Err(format!("ebpf helper {} exited with {:?}", helper, status.code()).into());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn backend_nft(src_did: &str, dst_did: &str, decision: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    let table = env::var("RITMA_FW_NFT_TABLE").unwrap_or_else(|_| "inet".to_string());
    let chain = env::var("RITMA_FW_NFT_CHAIN").unwrap_or_else(|_| "ritma_fw".to_string());

    ensure_nft_table_and_chain(&table, &chain)?;

    let src_set = slug_did_to_set(src_did);
    let dst_set = slug_did_to_set(dst_did);

    match decision {
        "deny" => {
            // Drop traffic from src_set to dst_set.
            let args = [
                "add", "rule",
                &table,
                &chain,
                "ip", "saddr",
                &format!("@{}", src_set),
                "ip", "daddr",
                &format!("@{}", dst_set),
                "drop",
            ];
            run_nft(&args)
        }
        "isolate" => {
            // Drop all traffic from src_set, regardless of destination.
            let args = [
                "add", "rule",
                &table,
                &chain,
                "ip", "saddr",
                &format!("@{}", src_set),
                "drop",
            ];
            run_nft(&args)
        }
        "allow" => {
            // Allow removes any existing drop rules for this (src_set, dst_set)
            // pair, treating nftables as a deny-list for this DID pair.
            println!(
                "[fw-helper] backend=nft src_did={} dst_did={} decision=allow (cleanup)",
                src_did, dst_did
            );
            cleanup_nft_drop_rules_for_pair(&table, &chain, &src_set, &dst_set)
        }
        "throttle" => {
            println!(
                "[fw-helper] backend=nft src_did={} dst_did={} decision=throttle (not implemented)",
                src_did, dst_did
            );
            Ok(())
        }
        other => {
            Err(format!("unsupported decision for nft backend: {}", other).into())
        }
    }
}

#[cfg(target_os = "linux")]
fn slug_did_to_set(did: &str) -> String {
    did.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => c,
            ':' => '_',
            _ => '_',
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn run_nft(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    println!("[fw-helper] backend=nft nft {}", args.join(" "));
    let status = Command::new("nft").args(args).status()?;
    if !status.success() {
        return Err(format!("nft exited with {:?}", status.code()).into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_nft_drop_rules_for_pair(
    table: &str,
    chain: &str,
    src_set: &str,
    dst_set: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // List chain with rule handles.
    let output = Command::new("nft")
        .args(["-a", "list", "chain", table, chain])
        .output()?;

    if !output.status.success() {
        println!(
            "[fw-helper] backend=nft failed to list chain {} {}: {:?}",
            table,
            chain,
            output.status.code()
        );
        return Ok(()); // best-effort cleanup
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let needle_src = format!("ip saddr @{}", src_set);
    let needle_dst = format!("ip daddr @{}", dst_set);

    let mut handles = Vec::new();
    for line in stdout.lines() {
        if !line.contains(&needle_src) || !line.contains(&needle_dst) {
            continue;
        }
        if !line.contains("drop") {
            continue;
        }

        // nft prints handles as: "... # handle 42"
        if let Some(idx) = line.rfind("handle ") {
            let handle_str = &line[idx + "handle ".len()..].trim();
            // handle_str may contain trailing comments; parse up to first space.
            let handle_token = handle_str
                .split_whitespace()
                .next()
                .unwrap_or("");
            if let Ok(h) = handle_token.parse::<u64>() {
                handles.push(h);
            }
        }
    }

    for h in handles {
        let h_str = h.to_string();
        let args = ["delete", "rule", table, chain, "handle", &h_str];
        if let Err(e) = run_nft(&args) {
            println!(
                "[fw-helper] backend=nft failed to delete rule handle {}: {}",
                h, e
            );
        }
    }

    Ok(())
}
