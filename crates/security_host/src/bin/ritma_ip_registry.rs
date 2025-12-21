// ritma-ip-registry: manages IP→DID mappings in BPF map
// This daemon watches for service registrations and updates the ip_to_did BPF map.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ritma-ip-registry is only supported on linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::io::{BufRead, BufReader};
    use std::process::Command;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    tracing_subscriber::fmt::init();

    let map_path = env::var("RITMA_IP_DID_MAP_PATH")
        .unwrap_or_else(|_| "/sys/fs/bpf/ip_to_did".to_string());

    tracing::info!("ritma-ip-registry starting, map_path={}", map_path);

    // Read IP→DID registrations from stdin (one per line)
    // Format: <ip_address> <did>
    // Example: 10.0.1.5 did:ritma:svc:acme:api

    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin);

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("failed to read line: {}", e);
                continue;
            }
        };

        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            tracing::warn!("invalid line (expected: <ip> <did>): {}", line);
            continue;
        }

        let ip_str = parts[0];
        let did_str = parts[1];

        // Parse IP address
        let ip_addr: std::net::Ipv4Addr = match ip_str.parse() {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!("invalid IP address {}: {}", ip_str, e);
                continue;
            }
        };

        // Hash DID to get numeric ID (same logic as ritma-ebpf-helper)
        fn did_to_id(did: &str) -> u32 {
            let mut hasher = DefaultHasher::new();
            did.hash(&mut hasher);
            (hasher.finish() & 0xFFFFFFFF) as u32
        }

        let did_id = did_to_id(did_str);

        // Convert IP to hex (network byte order)
        let ip_bytes = ip_addr.octets();
        let ip_hex = format!("{:02x}{:02x}{:02x}{:02x}",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

        // Convert DID ID to hex (little-endian u32)
        let did_id_hex = format!("{:02x}{:02x}{:02x}{:02x}",
            (did_id & 0xFF) as u8,
            ((did_id >> 8) & 0xFF) as u8,
            ((did_id >> 16) & 0xFF) as u8,
            ((did_id >> 24) & 0xFF) as u8);

        tracing::info!(
            "registering ip={} did={} did_id={} key_hex={} value_hex={}",
            ip_str, did_str, did_id, ip_hex, did_id_hex
        );

        // Update BPF map via bpftool
        let status = Command::new("bpftool")
            .args(["map", "update", "pinned", &map_path, "key", "hex", &ip_hex, "value", "hex", &did_id_hex])
            .status()?;

        if !status.success() {
            tracing::error!("bpftool map update failed for ip={} did={}: {:?}",
                ip_str, did_str, status.code());
        }
    }

    Ok(())
}
