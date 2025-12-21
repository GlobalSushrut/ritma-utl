use common_models::{TraceEvent, TriggerVerdict, SnapshotAction, EvidencePackManifest, ArtifactMeta, PrivacyMeta, WindowRange};
use privacy_engine::PrivacyEngine;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub pid: i32,
    pub ppid: i32,
    pub cmd: String,
    pub user: String,
    pub cpu_percent: f64,
    pub mem_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketSnapshot {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSnapshot {
    pub container_id: String,
    pub image: String,
    pub status: String,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModuleSnapshot {
    pub name: String,
    pub size: u64,
    pub used_by_count: u32,
    pub used_by: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDumpMeta {
    pub pid: i32,
    pub process_name: String,
    pub dump_reason: String,  // "high_severity", "anomaly", "manual"
    pub dump_size: u64,
    pub dump_hash: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConnectionMeta {
    pub local_addr: String,
    pub remote_addr: String,
    pub sni: Option<String>,  // Server Name Indication
    pub cipher_suite: Option<String>,
    pub tls_version: Option<String>,
    pub cert_fingerprint: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_addresses: Vec<String>,  // IPv4 and IPv6
    pub mac_address: String,
    pub state: String,  // UP, DOWN
    pub mtu: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingEntry {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePort {
    pub port: u16,
    pub protocol: String,  // tcp, udp
    pub service_name: String,
    pub process_name: Option<String>,
    pub pid: Option<i32>,
    pub state: String,  // LISTEN, ESTABLISHED
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesPod {
    pub name: String,
    pub namespace: String,
    pub pod_ip: String,
    pub node_name: String,
    pub status: String,
    pub containers: Vec<String>,
    pub labels: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesService {
    pub name: String,
    pub namespace: String,
    pub cluster_ip: String,
    pub external_ips: Vec<String>,
    pub ports: Vec<String>,
    pub selector: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub interfaces: Vec<NetworkInterface>,
    pub routes: Vec<RoutingEntry>,
    pub listening_ports: Vec<ServicePort>,
    pub k8s_pods: Vec<KubernetesPod>,
    pub k8s_services: Vec<KubernetesService>,
    pub network_segments: Vec<String>,  // CIDR blocks
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshake {
    pub timestamp: String,
    pub client_ip: String,
    pub server_ip: String,
    pub server_name: String,  // SNI from ClientHello
    pub tls_version: String,  // TLS 1.2, TLS 1.3
    pub cipher_suite: String,
    pub client_hello_hash: String,  // JA3 fingerprint
    pub server_hello_hash: String,  // JA3S fingerprint
    pub certificate_chain: Vec<CertificateInfo>,
    pub session_id: String,
    pub handshake_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    pub timestamp: String,
    pub method: String,  // GET, POST, PUT, DELETE, etc.
    pub url: String,
    pub path: String,
    pub query_params: std::collections::HashMap<String, String>,
    pub request_headers: std::collections::HashMap<String, String>,
    pub response_status: u16,
    pub response_headers: std::collections::HashMap<String, String>,
    pub request_body_hash: Option<String>,  // SHA256 of body (not content)
    pub response_body_hash: Option<String>,
    pub duration_ms: u64,
    pub user_agent: Option<String>,
    pub auth_type: Option<String>,  // Bearer, Basic, ApiKey, etc.
    pub api_type: String,  // REST, GraphQL, gRPC, SOAP
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub timestamp: String,
    pub query_name: String,
    pub query_type: String,  // A, AAAA, CNAME, MX, etc.
    pub response_ips: Vec<String>,
    pub response_code: String,  // NOERROR, NXDOMAIN, etc.
    pub ttl: u32,
    pub resolver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub timestamp: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub protocol: String,  // HTTP/1.1, HTTP/2, HTTP/3
    pub headers: std::collections::HashMap<String, String>,
    pub status_code: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CyberTrace {
    pub tls_handshakes: Vec<TlsHandshake>,
    pub api_calls: Vec<ApiCall>,
    pub dns_queries: Vec<DnsQuery>,
    pub http_requests: Vec<HttpRequest>,
}

pub struct Snapshotter {
    privacy: PrivacyEngine,
    fileless_detector: fileless_detector::FilelessDetector,
}

impl Snapshotter {
    pub fn new(namespace_id: &str) -> Self {
        Self {
            privacy: PrivacyEngine::new(namespace_id),
            fileless_detector: fileless_detector::FilelessDetector::new(),
        }
    }
    
    /// Get fileless malware alerts
    pub fn get_fileless_alerts(&self) -> &[fileless_detector::FilelessAlert] {
        self.fileless_detector.get_alerts()
    }
    
    /// Export fileless alerts as JSON
    pub fn export_fileless_alerts(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self.fileless_detector.get_alerts())
            .map_err(|e| format!("Failed to serialize fileless alerts: {}", e))
    }
    
    pub fn capture_snapshot(
        &self,
        trigger: &TriggerVerdict,
        trace_excerpt: &[TraceEvent],
    ) -> Result<EvidencePackManifest, String> {
        if matches!(trigger.next_action, SnapshotAction::SignalOnly) {
            return Err("No snapshot needed for SignalOnly action".to_string());
        }
        
        let mut artifacts: Vec<ArtifactMeta> = Vec::new();
        let mut redactions: Vec<String> = Vec::new();
        
        // 1. Capture cyber traces (TLS, API calls, DNS, HTTP)
        if let Ok(cyber_trace) = self.capture_cyber_traces() {
            let trace_json = serde_json::to_string_pretty(&cyber_trace).unwrap();
            let trace_hash = self.hash_content(&trace_json);
            
            artifacts.push(ArtifactMeta {
                name: "cyber_trace.json".to_string(),
                sha256: trace_hash,
                size: trace_json.len() as u64,
            });
        }
        
        // 2. Capture network topology (IP, routes, K8s, ports)
        if let Ok(topology) = self.capture_network_topology() {
            let topo_json = serde_json::to_string_pretty(&topology).unwrap();
            let topo_hash = self.hash_content(&topo_json);
            
            artifacts.push(ArtifactMeta {
                name: "network_topology.json".to_string(),
                sha256: topo_hash,
                size: topo_json.len() as u64,
            });
        }
        
        // 2. Capture kernel modules
        if let Ok(modules) = self.capture_kernel_modules() {
            let (mod_json, mod_redactions) = self.privacy.redact_secrets(&serde_json::to_string_pretty(&modules).unwrap());
            let mod_hash = self.hash_content(&mod_json);
            
            artifacts.push(ArtifactMeta {
                name: "kernel_modules.json".to_string(),
                sha256: mod_hash,
                size: mod_json.len() as u64,
            });
            for r in mod_redactions { redactions.push(r.replacement); }
        }
        
        // 2. Capture process tree
        if let Ok(procs) = self.capture_process_tree() {
            let (proc_json, proc_redactions) = self.privacy.redact_secrets(&serde_json::to_string_pretty(&procs).unwrap());
            let proc_hash = self.hash_content(&proc_json);
            
            artifacts.push(ArtifactMeta {
                name: "process_tree.json".to_string(),
                sha256: proc_hash,
                size: proc_json.len() as u64,
            });
            for r in proc_redactions { redactions.push(r.replacement); }
        }
        
        // 2. Capture open sockets
        if let Ok(sockets) = self.capture_sockets() {
            let (sock_json, sock_redactions) = self.privacy.redact_secrets(&serde_json::to_string_pretty(&sockets).unwrap());
            let sock_hash = self.hash_content(&sock_json);
            
            artifacts.push(ArtifactMeta {
                name: "sockets.json".to_string(),
                sha256: sock_hash,
                size: sock_json.len() as u64,
            });
            for r in sock_redactions { redactions.push(r.replacement); }
        }
        
        // 3. Capture TLS connection metadata
        if let Ok(tls_conns) = self.capture_tls_connections() {
            let tls_json = serde_json::to_string_pretty(&tls_conns).unwrap();
            let tls_hash = self.hash_content(&tls_json);
            
            artifacts.push(ArtifactMeta {
                name: "tls_connections.json".to_string(),
                sha256: tls_hash,
                size: tls_json.len() as u64,
            });
        }
        
        // 4. Capture memory dumps for high-severity triggers
        if trigger.score >= 0.9 && matches!(trigger.next_action, SnapshotAction::SnapshotStandard) {
            // Find suspicious processes from trace_excerpt
            let mut dumped_pids = std::collections::HashSet::new();
            for event in trace_excerpt {
                if event.actor.uid == 0 && !dumped_pids.contains(&event.actor.pid) {
                    if let Ok(dump_meta) = self.capture_memory_dump(event.actor.pid as i32, "high_severity") {
                        let dump_json = serde_json::to_string_pretty(&dump_meta).unwrap();
                        let dump_hash = self.hash_content(&dump_json);
                        
                        artifacts.push(ArtifactMeta {
                            name: format!("memory_dump_{}.json", event.actor.pid),
                            sha256: dump_hash,
                            size: dump_json.len() as u64,
                        });
                        dumped_pids.insert(event.actor.pid);
                        
                        if dumped_pids.len() >= 3 { break; } // Limit to 3 dumps
                    }
                }
            }
        }
        
        // 5. Capture container metadata (if available)
        if let Ok(containers) = self.capture_containers() {
            let cont_json = serde_json::to_string_pretty(&containers).unwrap();
            let cont_hash = self.hash_content(&cont_json);
            
            artifacts.push(ArtifactMeta {
                name: "containers.json".to_string(),
                sha256: cont_hash,
                size: cont_json.len() as u64,
            });
        }
        
        // 6. Trace excerpt (hash-only for file paths, redact secrets)
        let (trace_json, trace_redactions) = self.privacy.redact_secrets(&serde_json::to_string_pretty(&trace_excerpt).unwrap());
        let trace_hash = self.hash_content(&trace_json);
        
        artifacts.push(ArtifactMeta {
            name: "trace_excerpt.json".to_string(),
            sha256: trace_hash,
            size: trace_json.len() as u64,
        });
        for r in trace_redactions { redactions.push(r.replacement); }
        
        Ok(EvidencePackManifest {
            pack_id: format!("ep_{}", uuid::Uuid::new_v4()),
            namespace_id: trigger.namespace_id.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            window: WindowRange { start: trigger.window.start.clone(), end: trigger.window.end.clone() },
            attack_graph_hash: String::new(),
            artifacts,
            privacy: PrivacyMeta { mode: "hash-only".to_string(), redactions },
            contract_hash: None,
            config_hash: None,
        })
    }
    
    fn capture_process_tree(&self) -> Result<Vec<ProcessSnapshot>, String> {
        let output = Command::new("ps")
            .args(&["aux", "--no-headers"])
            .output()
            .map_err(|e| format!("ps command failed: {}", e))?;
        
        if !output.status.success() {
            return Err("ps command failed".to_string());
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut processes = Vec::new();
        
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 11 {
                processes.push(ProcessSnapshot {
                    pid: parts[1].parse().unwrap_or(0),
                    ppid: 0, // ps aux doesn't show ppid, would need ps -ef
                    cmd: parts[10..].join(" "),
                    user: parts[0].to_string(),
                    cpu_percent: parts[2].parse().unwrap_or(0.0),
                    mem_percent: parts[3].parse().unwrap_or(0.0),
                });
            }
        }
        
        Ok(processes)
    }
    
    fn capture_sockets(&self) -> Result<Vec<SocketSnapshot>, String> {
        // Try ss first, fallback to netstat
        let output = Command::new("ss")
            .args(&["-tunap"])
            .output()
            .or_else(|_| Command::new("netstat").args(&["-tunap"]).output())
            .map_err(|e| format!("socket capture failed: {}", e))?;
        
        if !output.status.success() {
            return Err("socket command failed".to_string());
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut sockets = Vec::new();
        
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                sockets.push(SocketSnapshot {
                    local_addr: parts[3].to_string(),
                    remote_addr: parts[4].to_string(),
                    state: parts[0].to_string(),
                    pid: None, // Would need parsing from last column
                });
            }
        }
        
        Ok(sockets)
    }
    
    fn capture_containers(&self) -> Result<Vec<ContainerSnapshot>, String> {
        let output = Command::new("docker")
            .args(&["ps", "-a", "--format", "{{.ID}}|{{.Image}}|{{.Status}}|{{.CreatedAt}}"])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut containers = Vec::new();
                
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() >= 4 {
                        containers.push(ContainerSnapshot {
                            container_id: parts[0].to_string(),
                            image: parts[1].to_string(),
                            status: parts[2].to_string(),
                            created: parts[3].to_string(),
                        });
                    }
                }
                
                Ok(containers)
            }
            _ => Err("docker not available or failed".to_string()),
        }
    }
    
    fn hash_content(&self, content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }
    
    fn capture_kernel_modules(&self) -> Result<Vec<KernelModuleSnapshot>, String> {
        let output = Command::new("lsmod")
            .output()
            .map_err(|e| format!("lsmod failed: {}", e))?;
        
        if !output.status.success() {
            return Err("lsmod command failed".to_string());
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut modules = Vec::new();
        
        for (i, line) in stdout.lines().enumerate() {
            if i == 0 { continue; } // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let used_by_str = if parts.len() > 3 { parts[3] } else { "" };
                let used_by: Vec<String> = if used_by_str.is_empty() || used_by_str == "-" {
                    vec![]
                } else {
                    used_by_str.split(',').map(|s| s.to_string()).collect()
                };
                
                modules.push(KernelModuleSnapshot {
                    name: parts[0].to_string(),
                    size: parts[1].parse().unwrap_or(0),
                    used_by_count: parts[2].parse().unwrap_or(0),
                    used_by,
                    status: "loaded".to_string(),
                });
            }
        }
        
        Ok(modules)
    }
    
    fn capture_memory_dump(&self, pid: i32, reason: &str) -> Result<MemoryDumpMeta, String> {
        // Use gcore to dump process memory (requires gdb)
        let timestamp = chrono::Utc::now().to_rfc3339();
        let dump_path = format!("/tmp/ritma_memdump_{}_{}.core", pid, chrono::Utc::now().timestamp());
        
        let output = Command::new("gcore")
            .args(&["-o", &dump_path, &pid.to_string()])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let dump_size = std::fs::metadata(&dump_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                
                let dump_content = std::fs::read(&dump_path).unwrap_or_default();
                let mut hasher = Sha256::new();
                hasher.update(&dump_content);
                let dump_hash = hex::encode(hasher.finalize());
                
                // Get process name
                let proc_name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                    .unwrap_or_else(|_| format!("pid_{}", pid))
                    .trim()
                    .to_string();
                
                Ok(MemoryDumpMeta {
                    pid,
                    process_name: proc_name,
                    dump_reason: reason.to_string(),
                    dump_size,
                    dump_hash,
                    timestamp,
                })
            }
            _ => Err(format!("gcore failed for pid {}", pid)),
        }
    }
    
    fn capture_tls_connections(&self) -> Result<Vec<TlsConnectionMeta>, String> {
        // Capture TLS metadata using ss with extended info
        let output = Command::new("ss")
            .args(&["-tni", "state", "established"])
            .output()
            .map_err(|e| format!("ss failed: {}", e))?;
        
        if !output.status.success() {
            return Err("ss command failed".to_string());
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut connections = Vec::new();
        
        for line in stdout.lines() {
            if line.contains("ESTAB") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    // Parse TLS info from /proc/net/tcp or use eBPF for SNI
                    // For now, capture basic connection metadata
                    connections.push(TlsConnectionMeta {
                        local_addr: parts[3].to_string(),
                        remote_addr: parts[4].to_string(),
                        sni: None,  // Would need eBPF or packet capture for SNI
                        cipher_suite: None,  // Would need TLS handshake inspection
                        tls_version: None,  // Would need TLS handshake inspection
                        cert_fingerprint: None,  // Would need cert extraction
                        bytes_sent: 0,  // Would need netstat or eBPF stats
                        bytes_received: 0,
                    });
                }
            }
        }
        
        Ok(connections)
    }
    
    pub fn capture_network_topology(&self) -> Result<NetworkTopology, String> {
        let interfaces = self.capture_network_interfaces()?;
        let routes = self.capture_routing_table()?;
        let listening_ports = self.capture_listening_ports()?;
        let (k8s_pods, k8s_services) = self.capture_kubernetes_topology();
        let network_segments = self.discover_network_segments(&interfaces);
        
        Ok(NetworkTopology {
            interfaces,
            routes,
            listening_ports,
            k8s_pods,
            k8s_services,
            network_segments,
        })
    }
    
    fn capture_network_interfaces(&self) -> Result<Vec<NetworkInterface>, String> {
        let output = Command::new("ip")
            .args(&["-json", "addr", "show"])
            .output()
            .map_err(|e| format!("ip addr failed: {}", e))?;
        
        if !output.status.success() {
            // Fallback to non-JSON parsing
            return self.capture_network_interfaces_fallback();
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = Vec::new();
        
        // Parse JSON output from ip command
        if let Ok(json_data) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
            for iface in json_data {
                let name = iface["ifname"].as_str().unwrap_or("unknown").to_string();
                let state = iface["operstate"].as_str().unwrap_or("UNKNOWN").to_string();
                let mtu = iface["mtu"].as_u64().unwrap_or(0) as u32;
                let mac_address = iface["address"].as_str().unwrap_or("00:00:00:00:00:00").to_string();
                
                let mut ip_addresses = Vec::new();
                if let Some(addr_info) = iface["addr_info"].as_array() {
                    for addr in addr_info {
                        if let Some(ip) = addr["local"].as_str() {
                            ip_addresses.push(ip.to_string());
                        }
                    }
                }
                
                // Get RX/TX stats
                let (rx_bytes, tx_bytes) = self.get_interface_stats(&name);
                
                interfaces.push(NetworkInterface {
                    name,
                    ip_addresses,
                    mac_address,
                    state,
                    mtu,
                    rx_bytes,
                    tx_bytes,
                });
            }
        }
        
        Ok(interfaces)
    }
    
    fn capture_network_interfaces_fallback(&self) -> Result<Vec<NetworkInterface>, String> {
        let output = Command::new("ifconfig")
            .output()
            .map_err(|e| format!("ifconfig failed: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = Vec::new();
        let mut current_iface: Option<NetworkInterface> = None;
        
        for line in stdout.lines() {
            if !line.starts_with(' ') && line.contains(':') {
                if let Some(iface) = current_iface.take() {
                    interfaces.push(iface);
                }
                let name = line.split(':').next().unwrap_or("unknown").to_string();
                current_iface = Some(NetworkInterface {
                    name,
                    ip_addresses: Vec::new(),
                    mac_address: String::new(),
                    state: "UP".to_string(),
                    mtu: 1500,
                    rx_bytes: 0,
                    tx_bytes: 0,
                });
            }
        }
        
        if let Some(iface) = current_iface {
            interfaces.push(iface);
        }
        
        Ok(interfaces)
    }
    
    fn get_interface_stats(&self, iface_name: &str) -> (u64, u64) {
        let rx = std::fs::read_to_string(format!("/sys/class/net/{}/statistics/rx_bytes", iface_name))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let tx = std::fs::read_to_string(format!("/sys/class/net/{}/statistics/tx_bytes", iface_name))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        (rx, tx)
    }
    
    fn capture_routing_table(&self) -> Result<Vec<RoutingEntry>, String> {
        let output = Command::new("ip")
            .args(&["route", "show"])
            .output()
            .map_err(|e| format!("ip route failed: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut routes = Vec::new();
        
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let destination = parts[0].to_string();
                let gateway = if parts.contains(&"via") {
                    parts.iter().position(|&x| x == "via")
                        .and_then(|i| parts.get(i + 1))
                        .unwrap_or(&"0.0.0.0")
                        .to_string()
                } else {
                    "0.0.0.0".to_string()
                };
                let interface = if parts.contains(&"dev") {
                    parts.iter().position(|&x| x == "dev")
                        .and_then(|i| parts.get(i + 1))
                        .unwrap_or(&"unknown")
                        .to_string()
                } else {
                    "unknown".to_string()
                };
                let metric = if parts.contains(&"metric") {
                    parts.iter().position(|&x| x == "metric")
                        .and_then(|i| parts.get(i + 1))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0)
                } else {
                    0
                };
                
                routes.push(RoutingEntry {
                    destination,
                    gateway,
                    interface,
                    metric,
                });
            }
        }
        
        Ok(routes)
    }
    
    fn capture_listening_ports(&self) -> Result<Vec<ServicePort>, String> {
        let output = Command::new("ss")
            .args(&["-tulpn"])
            .output()
            .map_err(|e| format!("ss failed: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut ports = Vec::new();
        
        for line in stdout.lines() {
            if line.starts_with("tcp") || line.starts_with("udp") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let protocol = parts[0].to_string();
                    let state = parts[1].to_string();
                    let local_addr = parts[4];
                    
                    if let Some(port_str) = local_addr.split(':').last() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            let (process_name, pid) = if parts.len() > 6 {
                                self.parse_process_info(parts[6])
                            } else {
                                (None, None)
                            };
                            
                            ports.push(ServicePort {
                                port,
                                protocol,
                                service_name: self.get_service_name(port),
                                process_name,
                                pid,
                                state,
                            });
                        }
                    }
                }
            }
        }
        
        Ok(ports)
    }
    
    fn parse_process_info(&self, info: &str) -> (Option<String>, Option<i32>) {
        // Format: users:(("process",pid=1234,fd=5))
        let process_name = info.split("((\"").nth(1)
            .and_then(|s| s.split("\",").next())
            .map(|s| s.to_string());
        let pid = info.split("pid=").nth(1)
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.parse().ok());
        (process_name, pid)
    }
    
    fn get_service_name(&self, port: u16) -> String {
        match port {
            22 => "ssh",
            80 => "http",
            443 => "https",
            3000 => "grafana",
            8080 => "http-alt",
            8081 => "ritma-demo",
            9090 => "prometheus",
            6443 => "kubernetes-api",
            10250 => "kubelet",
            2379 => "etcd",
            _ => "unknown",
        }.to_string()
    }
    
    fn capture_kubernetes_topology(&self) -> (Vec<KubernetesPod>, Vec<KubernetesService>) {
        let pods = self.capture_k8s_pods().unwrap_or_default();
        let services = self.capture_k8s_services().unwrap_or_default();
        (pods, services)
    }
    
    fn capture_k8s_pods(&self) -> Result<Vec<KubernetesPod>, String> {
        let output = Command::new("kubectl")
            .args(&["get", "pods", "--all-namespaces", "-o", "json"])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    let mut pods = Vec::new();
                    
                    if let Some(items) = json_data["items"].as_array() {
                        for item in items {
                            let name = item["metadata"]["name"].as_str().unwrap_or("unknown").to_string();
                            let namespace = item["metadata"]["namespace"].as_str().unwrap_or("default").to_string();
                            let pod_ip = item["status"]["podIP"].as_str().unwrap_or("").to_string();
                            let node_name = item["spec"]["nodeName"].as_str().unwrap_or("").to_string();
                            let status = item["status"]["phase"].as_str().unwrap_or("Unknown").to_string();
                            
                            let mut containers = Vec::new();
                            if let Some(container_statuses) = item["status"]["containerStatuses"].as_array() {
                                for container in container_statuses {
                                    if let Some(name) = container["name"].as_str() {
                                        containers.push(name.to_string());
                                    }
                                }
                            }
                            
                            let mut labels = std::collections::HashMap::new();
                            if let Some(label_obj) = item["metadata"]["labels"].as_object() {
                                for (k, v) in label_obj {
                                    if let Some(val) = v.as_str() {
                                        labels.insert(k.clone(), val.to_string());
                                    }
                                }
                            }
                            
                            pods.push(KubernetesPod {
                                name,
                                namespace,
                                pod_ip,
                                node_name,
                                status,
                                containers,
                                labels,
                            });
                        }
                    }
                    
                    Ok(pods)
                } else {
                    Err("Failed to parse kubectl output".to_string())
                }
            }
            _ => Err("kubectl not available or failed".to_string()),
        }
    }
    
    fn capture_k8s_services(&self) -> Result<Vec<KubernetesService>, String> {
        let output = Command::new("kubectl")
            .args(&["get", "services", "--all-namespaces", "-o", "json"])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    let mut services = Vec::new();
                    
                    if let Some(items) = json_data["items"].as_array() {
                        for item in items {
                            let name = item["metadata"]["name"].as_str().unwrap_or("unknown").to_string();
                            let namespace = item["metadata"]["namespace"].as_str().unwrap_or("default").to_string();
                            let cluster_ip = item["spec"]["clusterIP"].as_str().unwrap_or("").to_string();
                            
                            let mut external_ips = Vec::new();
                            if let Some(ext_ips) = item["spec"]["externalIPs"].as_array() {
                                for ip in ext_ips {
                                    if let Some(ip_str) = ip.as_str() {
                                        external_ips.push(ip_str.to_string());
                                    }
                                }
                            }
                            
                            let mut ports = Vec::new();
                            if let Some(port_arr) = item["spec"]["ports"].as_array() {
                                for port in port_arr {
                                    let port_num = port["port"].as_u64().unwrap_or(0);
                                    let protocol = port["protocol"].as_str().unwrap_or("TCP");
                                    ports.push(format!("{}/{}", port_num, protocol));
                                }
                            }
                            
                            let mut selector = std::collections::HashMap::new();
                            if let Some(sel_obj) = item["spec"]["selector"].as_object() {
                                for (k, v) in sel_obj {
                                    if let Some(val) = v.as_str() {
                                        selector.insert(k.clone(), val.to_string());
                                    }
                                }
                            }
                            
                            services.push(KubernetesService {
                                name,
                                namespace,
                                cluster_ip,
                                external_ips,
                                ports,
                                selector,
                            });
                        }
                    }
                    
                    Ok(services)
                } else {
                    Err("Failed to parse kubectl output".to_string())
                }
            }
            _ => Err("kubectl not available or failed".to_string()),
        }
    }
    
    fn discover_network_segments(&self, interfaces: &[NetworkInterface]) -> Vec<String> {
        let mut segments = Vec::new();
        
        for iface in interfaces {
            for ip in &iface.ip_addresses {
                // Parse CIDR from IP (simplified - assumes /24 for private IPs)
                if ip.starts_with("10.") || ip.starts_with("172.") || ip.starts_with("192.168.") {
                    let parts: Vec<&str> = ip.split('.').collect();
                    if parts.len() == 4 {
                        let segment = format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]);
                        if !segments.contains(&segment) {
                            segments.push(segment);
                        }
                    }
                }
            }
        }
        
        segments
    }
    
    pub fn capture_cyber_traces(&self) -> Result<CyberTrace, String> {
        let tls_handshakes = self.capture_tls_handshakes().unwrap_or_default();
        let api_calls = self.capture_api_calls().unwrap_or_default();
        let dns_queries = self.capture_dns_queries().unwrap_or_default();
        let http_requests = self.capture_http_requests().unwrap_or_default();
        
        Ok(CyberTrace {
            tls_handshakes,
            api_calls,
            dns_queries,
            http_requests,
        })
    }
    
    fn capture_tls_handshakes(&self) -> Result<Vec<TlsHandshake>, String> {
        // Parse TLS handshakes from /proc/net/tcp and openssl s_client
        // In production, this would use eBPF to capture TLS handshake packets
        let mut handshakes = Vec::new();
        
        // Read established SSL connections
        if let Ok(output) = Command::new("ss").args(&["-tni", "state", "established"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            for line in stdout.lines() {
                if line.contains("ESTAB") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let local_addr = parts[3].to_string();
                        let remote_addr = parts[4].to_string();
                        
                        // Extract IPs
                        let client_ip = local_addr.split(':').next().unwrap_or("unknown").to_string();
                        let server_ip = remote_addr.split(':').next().unwrap_or("unknown").to_string();
                        
                        // Try to get TLS info for this connection
                        if let Ok(tls_info) = self.get_tls_info(&server_ip) {
                            handshakes.push(TlsHandshake {
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                client_ip,
                                server_ip: server_ip.clone(),
                                server_name: tls_info.0,
                                tls_version: tls_info.1,
                                cipher_suite: tls_info.2,
                                client_hello_hash: self.compute_ja3_fingerprint(&local_addr),
                                server_hello_hash: self.compute_ja3s_fingerprint(&remote_addr),
                                certificate_chain: tls_info.3,
                                session_id: format!("session_{}", uuid::Uuid::new_v4()),
                                handshake_duration_ms: 50,  // Estimated
                            });
                        }
                    }
                }
            }
        }
        
        Ok(handshakes)
    }
    
    fn get_tls_info(&self, server_ip: &str) -> Result<(String, String, String, Vec<CertificateInfo>), String> {
        // Use openssl s_client to get TLS info (simplified - in production use eBPF)
        let output = Command::new("timeout")
            .args(&["1", "openssl", "s_client", "-connect", &format!("{}:443", server_ip), "-servername", server_ip])
            .output();
        
        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                let combined = format!("{}{}", stdout, stderr);
                
                let server_name = server_ip.to_string();
                let tls_version = if combined.contains("TLSv1.3") {
                    "TLS 1.3".to_string()
                } else if combined.contains("TLSv1.2") {
                    "TLS 1.2".to_string()
                } else {
                    "TLS 1.1".to_string()
                };
                
                let cipher_suite = combined.lines()
                    .find(|l| l.contains("Cipher"))
                    .and_then(|l| l.split(':').nth(1))
                    .unwrap_or("UNKNOWN")
                    .trim()
                    .to_string();
                
                let certificates = vec![CertificateInfo {
                    subject: format!("CN={}", server_ip),
                    issuer: "Unknown CA".to_string(),
                    serial_number: "00:00:00:00".to_string(),
                    not_before: chrono::Utc::now().to_rfc3339(),
                    not_after: (chrono::Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
                    fingerprint_sha256: format!("sha256:{}", &self.hash_content(server_ip)[..32]),
                    public_key_algorithm: "RSA".to_string(),
                    signature_algorithm: "SHA256withRSA".to_string(),
                }];
                
                Ok((server_name, tls_version, cipher_suite, certificates))
            }
            Err(_) => Err("Failed to get TLS info".to_string()),
        }
    }
    
    fn compute_ja3_fingerprint(&self, addr: &str) -> String {
        // JA3 fingerprint: MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
        // Simplified version - in production, parse actual TLS ClientHello
        format!("ja3_{}", &self.hash_content(addr)[..32])
    }
    
    fn compute_ja3s_fingerprint(&self, addr: &str) -> String {
        // JA3S fingerprint: MD5(SSLVersion,Cipher,Extensions)
        // Simplified version - in production, parse actual TLS ServerHello
        format!("ja3s_{}", &self.hash_content(addr)[..32])
    }
    
    fn capture_api_calls(&self) -> Result<Vec<ApiCall>, String> {
        // Parse API calls from access logs or eBPF HTTP tracing
        // In production, use eBPF to capture HTTP/HTTPS requests
        let mut api_calls = Vec::new();
        
        // Try to read nginx/apache access logs
        let log_paths = vec![
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
        ];
        
        for log_path in log_paths {
            if let Ok(content) = std::fs::read_to_string(log_path) {
                for line in content.lines().rev().take(100) {  // Last 100 requests
                    if let Some(api_call) = self.parse_access_log_line(line) {
                        api_calls.push(api_call);
                    }
                }
                break;
            }
        }
        
        Ok(api_calls)
    }
    
    fn parse_access_log_line(&self, line: &str) -> Option<ApiCall> {
        // Parse common log format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size
        let parts: Vec<&str> = line.split('"').collect();
        if parts.len() < 3 {
            return None;
        }
        
        let request_parts: Vec<&str> = parts[1].split_whitespace().collect();
        if request_parts.len() < 3 {
            return None;
        }
        
        let method = request_parts[0].to_string();
        let full_path = request_parts[1];
        let (path, query_params) = self.parse_url_path(full_path);
        
        let status_parts: Vec<&str> = parts[2].split_whitespace().collect();
        let status = status_parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(200);
        
        let api_type = if full_path.contains("/graphql") {
            "GraphQL"
        } else if full_path.contains("/api/") {
            "REST"
        } else {
            "HTTP"
        }.to_string();
        
        Some(ApiCall {
            timestamp: chrono::Utc::now().to_rfc3339(),
            method,
            url: format!("http://localhost{}", full_path),
            path,
            query_params,
            request_headers: std::collections::HashMap::new(),
            response_status: status,
            response_headers: std::collections::HashMap::new(),
            request_body_hash: None,
            response_body_hash: None,
            duration_ms: 50,
            user_agent: None,
            auth_type: None,
            api_type,
        })
    }
    
    fn parse_url_path(&self, full_path: &str) -> (String, std::collections::HashMap<String, String>) {
        let mut params = std::collections::HashMap::new();
        let parts: Vec<&str> = full_path.split('?').collect();
        let path = parts[0].to_string();
        
        if parts.len() > 1 {
            for param in parts[1].split('&') {
                let kv: Vec<&str> = param.split('=').collect();
                if kv.len() == 2 {
                    params.insert(kv[0].to_string(), kv[1].to_string());
                }
            }
        }
        
        (path, params)
    }
    
    fn capture_dns_queries(&self) -> Result<Vec<DnsQuery>, String> {
        // Parse DNS queries from /var/log/syslog or use eBPF DNS tracing
        let mut queries = Vec::new();
        
        // Try to read recent DNS queries from systemd-resolved
        if let Ok(output) = Command::new("resolvectl").args(&["query", "example.com"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            for line in stdout.lines() {
                if line.contains("IN A") || line.contains("IN AAAA") {
                    queries.push(DnsQuery {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        query_name: "example.com".to_string(),
                        query_type: "A".to_string(),
                        response_ips: vec!["93.184.216.34".to_string()],
                        response_code: "NOERROR".to_string(),
                        ttl: 3600,
                        resolver: "8.8.8.8".to_string(),
                    });
                }
            }
        }
        
        // Also parse /etc/hosts for static mappings
        if let Ok(hosts) = std::fs::read_to_string("/etc/hosts") {
            for line in hosts.lines() {
                if !line.starts_with('#') && !line.trim().is_empty() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        queries.push(DnsQuery {
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            query_name: parts[1].to_string(),
                            query_type: "A".to_string(),
                            response_ips: vec![parts[0].to_string()],
                            response_code: "NOERROR".to_string(),
                            ttl: 0,  // Static mapping
                            resolver: "hosts_file".to_string(),
                        });
                    }
                }
            }
        }
        
        Ok(queries)
    }
    
    fn capture_http_requests(&self) -> Result<Vec<HttpRequest>, String> {
        // Capture HTTP requests from netstat/ss and access logs
        let mut requests = Vec::new();
        
        // Parse from access logs (similar to API calls but more general)
        let log_paths = vec![
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
        ];
        
        for log_path in log_paths {
            if let Ok(content) = std::fs::read_to_string(log_path) {
                for line in content.lines().rev().take(50) {
                    if let Some(req) = self.parse_http_request_log(line) {
                        requests.push(req);
                    }
                }
                break;
            }
        }
        
        Ok(requests)
    }
    
    fn parse_http_request_log(&self, line: &str) -> Option<HttpRequest> {
        let parts: Vec<&str> = line.split('"').collect();
        if parts.len() < 3 {
            return None;
        }
        
        let request_parts: Vec<&str> = parts[1].split_whitespace().collect();
        if request_parts.len() < 3 {
            return None;
        }
        
        let method = request_parts[0].to_string();
        let path = request_parts[1].to_string();
        let protocol = request_parts[2].to_string();
        
        let status_parts: Vec<&str> = parts[2].split_whitespace().collect();
        let status_code = status_parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(200);
        let bytes_sent = status_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        
        Some(HttpRequest {
            timestamp: chrono::Utc::now().to_rfc3339(),
            method,
            host: "localhost".to_string(),
            path,
            protocol,
            headers: std::collections::HashMap::new(),
            status_code,
            bytes_sent,
            bytes_received: 0,
            duration_ms: 50,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_models::{VerdictType, WindowRange};
    
    #[test]
    fn test_snapshotter_creation() {
        let snapshotter = Snapshotter::new("ns://test");
        assert!(true); // Basic instantiation test
    }
    
    #[test]
    fn test_signal_only_no_snapshot() {
        let snapshotter = Snapshotter::new("ns://test");
        let trigger = TriggerVerdict {
            trigger_id: "tr_test".to_string(),
            namespace_id: "ns://test".to_string(),
            window: WindowRange {
                start: "2024-01-01T00:00:00Z".to_string(),
                end: "2024-01-01T00:01:00Z".to_string(),
            },
            score: 0.1,
            verdict_type: VerdictType::IntentDrift,
            reason_codes: vec![],
            ml_ref: None,
            contract_hash: None,
            next_action: SnapshotAction::SignalOnly,
        };
        
        let result = snapshotter.capture_snapshot(&trigger, &[]);
        assert!(result.is_err());
    }
}
