use serde::{Deserialize, Serialize};

/// Basic DID type for security identities in Ritma.
///
/// Examples:
/// - did:ritma:tenant:acme
/// - did:ritma:svc:acme:public_api
/// - did:ritma:zone:acme:internal
/// - did:ritma:id:acme:user-123
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(String);

impl Did {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        if !s.starts_with("did:ritma:") {
            return Err("DID must start with did:ritma:".to_string());
        }
        Ok(Did(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn kind(&self) -> DidKind {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() < 3 {
            return DidKind::Unknown;
        }
        match parts.get(2).copied() {
            Some("tenant") => DidKind::Tenant,
            Some("svc") => DidKind::Service,
            Some("zone") => DidKind::Zone,
            Some("id") => DidKind::Identity,
            _ => DidKind::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidKind {
    Tenant,
    Service,
    Zone,
    Identity,
    Unknown,
}

/// Scope of isolation for OS-level enforcement (cgroups, namespaces, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationScope {
    Service,  // did:ritma:svc:...
    Zone,     // did:ritma:zone:...
    Tenant,   // did:ritma:tenant:...
}

/// Simple isolation profile that a controller can apply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IsolationProfile {
    pub cpu_limit_pct: Option<u8>,   // 0-100
    pub memory_limit_mb: Option<u64>,
    pub network_egress: Option<bool>,
    pub network_ingress: Option<bool>,
}

/// High-level decision for a network or RPC flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDecision {
    Allow,
    Deny,
    Throttle { rate_per_sec: u32 },
    Isolate { ttl_secs: u64 },
}

/// Abstract controller that can apply cgroup-style isolation.
pub trait CgroupController {
    fn apply_profile(&self, scope: IsolationScope, did: &Did, profile: IsolationProfile)
        -> Result<(), String>;
}

/// Abstract controller that can enforce firewall-style decisions between DIDs.
pub trait FirewallController {
    fn enforce_flow(&self, src: &Did, dst: &Did, decision: FlowDecision)
        -> Result<(), String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsIdentity {
    pub subject: String,
    pub dns_names: Vec<String>,
    pub san_uris: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    pub ca_bundle_path: String,
    pub cert_path: String,
    pub key_path: String,
    pub require_client_auth: bool,
}

/// Build a rustls ServerConfig from an MtlsConfig.
/// If require_client_auth is true and ca_bundle_path is set, enables mTLS.
pub fn build_rustls_server_config_from_mtls(
    cfg: &MtlsConfig,
) -> Result<std::sync::Arc<rustls::ServerConfig>, String> {
    use std::fs::File;
    use std::io::BufReader;

    use rustls::{Certificate, PrivateKey, ServerConfig, RootCertStore};
    use rustls::server::AllowAnyAuthenticatedClient;

    fn load_certs(path: &str) -> Result<Vec<Certificate>, String> {
        let f = File::open(path).map_err(|e| format!("failed to open cert {}: {}", path, e))?;
        let mut reader = BufReader::new(f);
        let certs = rustls_pemfile::certs(&mut reader)
            .map_err(|e| format!("failed to read certs from {}: {}", path, e))?;
        Ok(certs.into_iter().map(Certificate).collect())
    }

    fn load_private_key(path: &str) -> Result<PrivateKey, String> {
        let f = File::open(path).map_err(|e| format!("failed to open key {}: {}", path, e))?;
        let mut reader = BufReader::new(f);
        let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .map_err(|e| format!("failed to read private key from {}: {}", path, e))?;
        let key = keys.into_iter().next().ok_or_else(|| format!("no private keys in {}", path))?;
        Ok(PrivateKey(key))
    }

    let certs = load_certs(&cfg.cert_path)?;
    let key = load_private_key(&cfg.key_path)?;

    let server_config = if cfg.require_client_auth && !cfg.ca_bundle_path.is_empty() {
        // Enable mTLS: require client certs verified against CA bundle.
        let ca_certs = load_certs(&cfg.ca_bundle_path)?;
        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(&cert)
                .map_err(|e| format!("failed to add CA cert: {}", e))?;
        }
        let client_verifier = AllowAnyAuthenticatedClient::new(root_store);

        ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(std::sync::Arc::new(client_verifier))
            .with_single_cert(certs, key)
            .map_err(|e| format!("failed to build ServerConfig with client auth: {}", e))?
    } else {
        // Server TLS only, no client auth.
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("failed to build ServerConfig: {}", e))?
    };

    Ok(std::sync::Arc::new(server_config))
}

/// Extract an MtlsIdentity from a chain of rustls Certificates, if present.
pub fn mtls_identity_from_rustls_certs(certs: &[rustls::Certificate]) -> Option<MtlsIdentity> {
    use x509_parser::prelude::*;
    use x509_parser::extensions::GeneralName;

    let first = certs.first()?;
    let der = &first.0;
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject = cert.subject().to_string();
    let mut dns_names = Vec::new();
    let mut san_uris = Vec::new();

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in san.value.general_names.iter() {
            match gn {
                GeneralName::DNSName(dns) => dns_names.push(dns.to_string()),
                GeneralName::URI(uri) => san_uris.push(uri.to_string()),
                _ => {}
            }
        }
    }

    Some(MtlsIdentity {
        subject,
        dns_names,
        san_uris,
    })
}

/// Best-effort mapping from an MtlsIdentity to a Ritma Did.
pub fn did_from_mtls_identity(id: &MtlsIdentity) -> Option<Did> {
    for uri in &id.san_uris {
        if uri.starts_with("did:ritma:") {
            if let Ok(did) = Did::parse(uri) {
                return Some(did);
            }
        }
    }

    if id.subject.starts_with("did:ritma:") {
        if let Ok(did) = Did::parse(&id.subject) {
            return Some(did);
        }
    }

    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsNamespaceProfile {
    pub chroot_path: Option<String>,
    pub read_only_paths: Vec<String>,
    pub masked_paths: Vec<String>,
}

pub trait NamespaceController {
    fn apply_fs_namespace(
        &self,
        scope: IsolationScope,
        did: &Did,
        profile: &FsNamespaceProfile,
    ) -> Result<(), String>;
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    /// Linux-aware stub implementation of CgroupController that currently logs
    /// intended changes. This is the anchor point for real cgroup v2 wiring.
    pub struct LoggingLinuxCgroupController {
        pub cgroup_root: String,
    }

    impl LoggingLinuxCgroupController {
        pub fn new(root: impl Into<String>) -> Self {
            Self { cgroup_root: root.into() }
        }
    }

    impl CgroupController for LoggingLinuxCgroupController {
        fn apply_profile(
            &self,
            scope: IsolationScope,
            did: &Did,
            profile: IsolationProfile,
        ) -> Result<(), String> {
            println!(
                "[linux_cgroup] root={} scope={:?} did={} profile={:?}",
                self.cgroup_root,
                scope,
                did.as_str(),
                profile,
            );
            Ok(())
        }
    }

    /// Cgroup v2 controller that writes real cgroup files under a configurable
    /// root. In production, cgroup_root should point at a mounted cgroup v2
    /// hierarchy (e.g. /sys/fs/cgroup/ritma). In tests, it can be a temp dir.
    pub struct CgroupV2Controller {
        pub cgroup_root: PathBuf,
    }

    impl CgroupV2Controller {
        pub fn new(root: impl Into<PathBuf>) -> Self {
            Self { cgroup_root: root.into() }
        }

        fn group_path(&self, scope: IsolationScope, did: &Did) -> PathBuf {
            let scope_dir = match scope {
                IsolationScope::Tenant => "tenants",
                IsolationScope::Zone => "zones",
                IsolationScope::Service => "services",
            };
            let slug = did.as_str().replace(':', "_");
            self.cgroup_root.join(scope_dir).join(slug)
        }

        fn write_cpu_max(&self, dir: &Path, pct: u8) -> std::io::Result<()> {
            if pct == 0 || pct >= 100 {
                return Ok(()); // 0/100 treated as unlimited for now.
            }
            let period_us: u64 = 100_000; // 100ms period.
            let quota = (period_us * pct as u64) / 100;
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(dir.join("cpu.max"))?;
            writeln!(file, "{} {}", quota, period_us)
        }

        fn write_memory_max(&self, dir: &Path, mb: u64) -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(dir.join("memory.max"))?;
            let bytes = mb * 1024 * 1024;
            writeln!(file, "{}", bytes)
        }

        /// Attach a PID to the cgroup associated with the given scope + DID by
        /// writing it into `cgroup.procs`. This expects that a cgroup v2
        /// hierarchy is mounted at `cgroup_root`.
        pub fn attach_pid(&self, scope: IsolationScope, did: &Did, pid: i32) -> std::io::Result<()> {
            let dir = self.group_path(scope, did);
            fs::create_dir_all(&dir)?;
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(dir.join("cgroup.procs"))?;
            writeln!(file, "{}", pid)
        }
    }

    impl CgroupController for CgroupV2Controller {
        fn apply_profile(
            &self,
            scope: IsolationScope,
            did: &Did,
            profile: IsolationProfile,
        ) -> Result<(), String> {
            let dir = self.group_path(scope, did);
            if let Err(e) = fs::create_dir_all(&dir) {
                return Err(format!("failed to create cgroup dir {:?}: {}", dir, e));
            }

            if let Some(pct) = profile.cpu_limit_pct {
                if let Err(e) = self.write_cpu_max(&dir, pct) {
                    eprintln!("failed to write cpu.max in {:?}: {}", dir, e);
                }
            }
            if let Some(mb) = profile.memory_limit_mb {
                if let Err(e) = self.write_memory_max(&dir, mb) {
                    eprintln!("failed to write memory.max in {:?}: {}", dir, e);
                }
            }

            Ok(())
        }
    }

    /// Linux-aware stub implementation of NamespaceController that logs
    /// filesystem namespace intents (chroot, read-only paths, masked paths).
    pub struct LoggingLinuxNamespaceController;

    impl NamespaceController for LoggingLinuxNamespaceController {
        fn apply_fs_namespace(
            &self,
            scope: IsolationScope,
            did: &Did,
            profile: &FsNamespaceProfile,
        ) -> Result<(), String> {
            println!(
                "[linux_ns] scope={:?} did={} profile={:?}",
                scope,
                did.as_str(),
                profile,
            );
            Ok(())
        }
    }
}

