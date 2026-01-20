//! Kubernetes Metadata Integration
//!
//! Provides Kubernetes pod, service, and namespace metadata enrichment
//! for trace events. Supports both in-cluster and out-of-cluster configurations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Kubernetes Pod metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodMetadata {
    pub name: String,
    pub namespace: String,
    pub uid: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub node_name: Option<String>,
    pub service_account: Option<String>,
    pub owner_references: Vec<OwnerReference>,
    pub container_statuses: Vec<ContainerStatus>,
    pub pod_ip: Option<String>,
    pub host_ip: Option<String>,
    pub phase: String,
    pub start_time: Option<String>,
}

/// Kubernetes owner reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerReference {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
}

/// Container status within a pod
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStatus {
    pub name: String,
    pub container_id: Option<String>,
    pub image: String,
    pub image_id: Option<String>,
    pub ready: bool,
    pub restart_count: i32,
    pub state: ContainerState,
}

/// Container state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainerState {
    Running {
        started_at: Option<String>,
    },
    Waiting {
        reason: Option<String>,
        message: Option<String>,
    },
    Terminated {
        exit_code: i32,
        reason: Option<String>,
        started_at: Option<String>,
        finished_at: Option<String>,
    },
    Unknown,
}

/// Kubernetes Service metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetadata {
    pub name: String,
    pub namespace: String,
    pub uid: String,
    pub labels: HashMap<String, String>,
    pub cluster_ip: Option<String>,
    pub external_ips: Vec<String>,
    pub ports: Vec<ServicePort>,
    pub service_type: String,
    pub selector: HashMap<String, String>,
}

/// Service port definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePort {
    pub name: Option<String>,
    pub port: i32,
    pub target_port: String,
    pub protocol: String,
    pub node_port: Option<i32>,
}

/// Kubernetes Namespace metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceMetadata {
    pub name: String,
    pub uid: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub phase: String,
}

/// Enriched trace context with K8s metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sTraceContext {
    pub pod: Option<PodMetadata>,
    pub service: Option<ServiceMetadata>,
    pub namespace: Option<NamespaceMetadata>,
    pub workload_name: Option<String>,
    pub workload_kind: Option<String>,
}

/// Cache entry with TTL
struct CacheEntry<T> {
    data: T,
    expires_at: Instant,
}

/// Kubernetes metadata provider
/// Fetches and caches K8s metadata for trace enrichment
pub struct K8sMetadataProvider {
    /// Cache: container_id -> PodMetadata
    pod_cache: Arc<RwLock<HashMap<String, CacheEntry<PodMetadata>>>>,
    /// Cache: (namespace, name) -> ServiceMetadata
    service_cache: Arc<RwLock<HashMap<(String, String), CacheEntry<ServiceMetadata>>>>,
    /// Cache: namespace -> NamespaceMetadata
    namespace_cache: Arc<RwLock<HashMap<String, CacheEntry<NamespaceMetadata>>>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// API server URL
    api_server: String,
    /// Service account token path
    token_path: String,
    /// CA cert path
    ca_path: String,
    /// Whether running in-cluster
    in_cluster: bool,
}

impl Default for K8sMetadataProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl K8sMetadataProvider {
    pub fn new() -> Self {
        let in_cluster =
            std::path::Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token").exists();

        Self {
            pod_cache: Arc::new(RwLock::new(HashMap::new())),
            service_cache: Arc::new(RwLock::new(HashMap::new())),
            namespace_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(60),
            api_server: std::env::var("KUBERNETES_SERVICE_HOST")
                .map(|h| {
                    let port = std::env::var("KUBERNETES_SERVICE_PORT")
                        .unwrap_or_else(|_| "443".to_string());
                    format!("https://{}:{}", h, port)
                })
                .unwrap_or_else(|_| "https://kubernetes.default.svc".to_string()),
            token_path: "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string(),
            ca_path: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".to_string(),
            in_cluster,
        }
    }

    pub fn with_config(api_server: String, token_path: String, ca_path: String) -> Self {
        Self {
            pod_cache: Arc::new(RwLock::new(HashMap::new())),
            service_cache: Arc::new(RwLock::new(HashMap::new())),
            namespace_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(60),
            api_server,
            token_path,
            ca_path,
            in_cluster: false,
        }
    }

    /// Check if K8s API is available
    pub fn is_available(&self) -> bool {
        self.in_cluster || std::path::Path::new(&self.token_path).exists()
    }

    /// Get pod metadata by container ID
    pub fn get_pod_by_container_id(&self, container_id: &str) -> Option<PodMetadata> {
        // Check cache first
        if let Ok(cache) = self.pod_cache.read() {
            if let Some(entry) = cache.get(container_id) {
                if entry.expires_at > Instant::now() {
                    return Some(entry.data.clone());
                }
            }
        }

        // Fetch from API (would need async in production)
        // For now, return None - actual implementation would use tokio/reqwest
        None
    }

    /// Get pod metadata by namespace and name
    pub fn get_pod(&self, namespace: &str, name: &str) -> Option<PodMetadata> {
        // Check cache
        let cache_key = format!("{}:{}", namespace, name);
        if let Ok(cache) = self.pod_cache.read() {
            if let Some(entry) = cache.get(&cache_key) {
                if entry.expires_at > Instant::now() {
                    return Some(entry.data.clone());
                }
            }
        }

        None
    }

    /// Get service metadata
    pub fn get_service(&self, namespace: &str, name: &str) -> Option<ServiceMetadata> {
        let key = (namespace.to_string(), name.to_string());

        if let Ok(cache) = self.service_cache.read() {
            if let Some(entry) = cache.get(&key) {
                if entry.expires_at > Instant::now() {
                    return Some(entry.data.clone());
                }
            }
        }

        None
    }

    /// Get namespace metadata
    pub fn get_namespace(&self, name: &str) -> Option<NamespaceMetadata> {
        if let Ok(cache) = self.namespace_cache.read() {
            if let Some(entry) = cache.get(name) {
                if entry.expires_at > Instant::now() {
                    return Some(entry.data.clone());
                }
            }
        }

        None
    }

    /// Enrich trace context with K8s metadata
    pub fn enrich_context(
        &self,
        container_id: Option<&str>,
        pod_ip: Option<&str>,
    ) -> K8sTraceContext {
        let mut ctx = K8sTraceContext {
            pod: None,
            service: None,
            namespace: None,
            workload_name: None,
            workload_kind: None,
        };

        // Try to get pod by container ID
        if let Some(cid) = container_id {
            if let Some(pod) = self.get_pod_by_container_id(cid) {
                // Extract workload info from owner references
                for owner in &pod.owner_references {
                    match owner.kind.as_str() {
                        "ReplicaSet" | "Deployment" | "StatefulSet" | "DaemonSet" | "Job"
                        | "CronJob" => {
                            ctx.workload_kind = Some(owner.kind.clone());
                            // For ReplicaSet, try to get parent Deployment name
                            if owner.kind == "ReplicaSet" {
                                // ReplicaSet name format: <deployment>-<hash>
                                if let Some(pos) = owner.name.rfind('-') {
                                    ctx.workload_name = Some(owner.name[..pos].to_string());
                                } else {
                                    ctx.workload_name = Some(owner.name.clone());
                                }
                            } else {
                                ctx.workload_name = Some(owner.name.clone());
                            }
                            break;
                        }
                        _ => {}
                    }
                }

                // Get namespace metadata
                ctx.namespace = self.get_namespace(&pod.namespace);
                ctx.pod = Some(pod);
            }
        }

        ctx
    }

    /// Cache pod metadata
    pub fn cache_pod(&self, container_id: &str, pod: PodMetadata) {
        if let Ok(mut cache) = self.pod_cache.write() {
            cache.insert(
                container_id.to_string(),
                CacheEntry {
                    data: pod,
                    expires_at: Instant::now() + self.cache_ttl,
                },
            );
        }
    }

    /// Cache service metadata
    pub fn cache_service(&self, namespace: &str, name: &str, service: ServiceMetadata) {
        if let Ok(mut cache) = self.service_cache.write() {
            cache.insert(
                (namespace.to_string(), name.to_string()),
                CacheEntry {
                    data: service,
                    expires_at: Instant::now() + self.cache_ttl,
                },
            );
        }
    }

    /// Cache namespace metadata
    pub fn cache_namespace(&self, name: &str, namespace: NamespaceMetadata) {
        if let Ok(mut cache) = self.namespace_cache.write() {
            cache.insert(
                name.to_string(),
                CacheEntry {
                    data: namespace,
                    expires_at: Instant::now() + self.cache_ttl,
                },
            );
        }
    }

    /// Cleanup expired cache entries
    pub fn cleanup_cache(&self) {
        let now = Instant::now();

        if let Ok(mut cache) = self.pod_cache.write() {
            cache.retain(|_, v| v.expires_at > now);
        }

        if let Ok(mut cache) = self.service_cache.write() {
            cache.retain(|_, v| v.expires_at > now);
        }

        if let Ok(mut cache) = self.namespace_cache.write() {
            cache.retain(|_, v| v.expires_at > now);
        }
    }
}

/// Parse container ID from cgroup path
/// Supports Docker, containerd, CRI-O formats
pub fn parse_container_id_from_cgroup(cgroup: &str) -> Option<String> {
    // Docker systemd: docker-<64hex>.scope
    // containerd: cri-containerd-<64hex>.scope
    // CRI-O: crio-<64hex>.scope
    // cgroupfs: /docker/<64hex> or /kubepods/.../<64hex>

    let prefixes = ["docker-", "cri-containerd-", "crio-", "containerd-"];

    for prefix in prefixes {
        if let Some(start) = cgroup.find(prefix) {
            let rest = &cgroup[start + prefix.len()..];
            let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() >= 12 {
                return Some(hex);
            }
        }
    }

    // Try cgroupfs format: /docker/<hex> or /kubepods/.../<hex>
    for segment in cgroup.split('/') {
        if segment.len() >= 64 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(segment.to_string());
        }
    }

    None
}

/// Parse pod UID from cgroup path
pub fn parse_pod_uid_from_cgroup(cgroup: &str) -> Option<String> {
    // Kubernetes cgroup paths contain pod UID:
    // /kubepods/burstable/pod<uid>/...
    // /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/...

    // Look for patterns like "-pod" or "/pod" followed by UID
    let patterns = ["-pod", "/pod"];

    for pattern in patterns {
        if let Some(pos) = cgroup.find(pattern) {
            let start = pos + pattern.len();
            let rest = &cgroup[start..];
            // UID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx or xxxxxxxx_xxxx_xxxx_xxxx_xxxxxxxxxxxx
            let uid: String = rest
                .chars()
                .take_while(|c| c.is_ascii_hexdigit() || *c == '-' || *c == '_')
                .collect();

            if uid.len() >= 32 {
                // Normalize underscores to dashes
                return Some(uid.replace('_', "-"));
            }
        }
    }

    None
}

/// Downward API reader for pod metadata
/// Reads from mounted volumes in /etc/podinfo/
pub struct DownwardApiReader {
    base_path: String,
}

impl Default for DownwardApiReader {
    fn default() -> Self {
        Self::new()
    }
}

impl DownwardApiReader {
    pub fn new() -> Self {
        Self {
            base_path: "/etc/podinfo".to_string(),
        }
    }

    pub fn with_path(base_path: String) -> Self {
        Self { base_path }
    }

    /// Check if downward API is available
    pub fn is_available(&self) -> bool {
        std::path::Path::new(&self.base_path).exists()
    }

    /// Read pod name
    pub fn pod_name(&self) -> Option<String> {
        self.read_file("name")
    }

    /// Read pod namespace
    pub fn pod_namespace(&self) -> Option<String> {
        self.read_file("namespace")
    }

    /// Read pod UID
    pub fn pod_uid(&self) -> Option<String> {
        self.read_file("uid")
    }

    /// Read pod labels
    pub fn pod_labels(&self) -> HashMap<String, String> {
        self.read_labels("labels")
    }

    /// Read pod annotations
    pub fn pod_annotations(&self) -> HashMap<String, String> {
        self.read_labels("annotations")
    }

    /// Read node name
    pub fn node_name(&self) -> Option<String> {
        self.read_file("node_name")
    }

    /// Read service account name
    pub fn service_account(&self) -> Option<String> {
        self.read_file("serviceaccount")
    }

    fn read_file(&self, name: &str) -> Option<String> {
        let path = format!("{}/{}", self.base_path, name);
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn read_labels(&self, name: &str) -> HashMap<String, String> {
        let mut labels = HashMap::new();
        let path = format!("{}/{}", self.base_path, name);

        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    labels.insert(
                        key.trim().trim_matches('"').to_string(),
                        value.trim().trim_matches('"').to_string(),
                    );
                }
            }
        }

        labels
    }

    /// Build PodMetadata from downward API
    pub fn build_pod_metadata(&self) -> Option<PodMetadata> {
        let name = self.pod_name()?;
        let namespace = self.pod_namespace()?;
        let uid = self.pod_uid().unwrap_or_default();

        Some(PodMetadata {
            name,
            namespace,
            uid,
            labels: self.pod_labels(),
            annotations: self.pod_annotations(),
            node_name: self.node_name(),
            service_account: self.service_account(),
            owner_references: Vec::new(),
            container_statuses: Vec::new(),
            pod_ip: None,
            host_ip: None,
            phase: "Running".to_string(),
            start_time: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_container_id_docker() {
        let cgroup = "0::/system.slice/docker-ae836c95b4c3c9e9179e0e91015512da89fdec91612f63cebae57df9a5444c79.scope";
        let cid = parse_container_id_from_cgroup(cgroup);
        assert_eq!(
            cid,
            Some("ae836c95b4c3c9e9179e0e91015512da89fdec91612f63cebae57df9a5444c79".to_string())
        );
    }

    #[test]
    fn test_parse_container_id_containerd() {
        let cgroup = "0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678.scope";
        let cid = parse_container_id_from_cgroup(cgroup);
        assert_eq!(
            cid,
            Some("deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678".to_string())
        );
    }

    #[test]
    fn test_parse_pod_uid() {
        let cgroup = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789012.slice/cri-containerd-abc.scope";
        let uid = parse_pod_uid_from_cgroup(cgroup);
        assert_eq!(
            uid,
            Some("12345678-1234-1234-1234-123456789012".to_string())
        );
    }

    #[test]
    fn test_k8s_provider_creation() {
        let provider = K8sMetadataProvider::new();
        // In non-K8s environment, should not be available
        // assert!(!provider.is_available()); // May pass in K8s
        assert!(provider.cache_ttl.as_secs() > 0);
    }

    #[test]
    fn test_enrich_context_empty() {
        let provider = K8sMetadataProvider::new();
        let ctx = provider.enrich_context(None, None);
        assert!(ctx.pod.is_none());
        assert!(ctx.service.is_none());
    }
}
