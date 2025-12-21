# Container & Kubernetes Security

Truthful-by-default. This crate provides grounded detectors for container/K8s risks with explicit evidence structures. It simulates inputs via library calls; it does not attach to a live cluster by itself.

## What it detects

- Container escape conditions
  - Privileged containers, dangerous host mounts, Docker socket exposure, dangerous capabilities
- Kubernetes API abuse
  - Excessive secret access, privilege escalation patterns
- Pod-to-pod lateral movement
  - Cross-namespace communications patterns
- Registry poisoning
  - Digest mismatches, suspicious layers, backdoor indicators

## Key types

- `ContainerSecurityManager`
  - `escape_detector()` -> `ContainerEscapeDetector`
  - `k8s_abuse_detector()` -> `K8sApiAbuseDetector`
  - `lateral_movement_detector()` -> `LateralMovementDetector`
  - `registry_poisoning_detector()` -> `RegistryPoisoningDetector`
  - `get_security_report()` -> aggregates all alerts

Evidence/alerts:
- `ContainerEscapeAlert { evidence: EscapeEvidence { privileged, host_mounts, capabilities, ... } }`
- `K8sApiAbuseAlert { user, abuse_type, api_calls, ... }`
- `LateralMovementAlert { source_namespace, target_namespace, network_connections }`
- `RegistryPoisoningAlert { expected_digest, actual_digest, suspicious_layers }`

## Usage

```rust
use container_security::{ContainerSecurityManager, ContainerInfo, K8sApiCall};

let mut csm = ContainerSecurityManager::new(3); // suspicious API threshold

// Escape checks
csm.escape_detector().register_container(ContainerInfo {
    container_id: "abc123".into(),
    container_name: "malicious".into(),
    privileged: true,
    host_mounts: vec!["/proc".into(), "/sys".into(), "/var/run/docker.sock".into()],
    capabilities: vec!["CAP_SYS_ADMIN".into(), "CAP_SYS_PTRACE".into()],
    pid_namespace: "host".into(),
    network_namespace: "host".into(),
});
for a in csm.escape_detector().check_escape_attempts("abc123") {
    eprintln!("ESCAPE: {}", a.description);
}

// K8s API abuse
for i in 0..5 {
    csm.k8s_abuse_detector().record_api_call(
        "attacker".into(),
        K8sApiCall { timestamp: chrono::Utc::now().to_rfc3339(), verb: "GET".into(), resource: "secrets".into(), namespace: "default".into(), name: Some(format!("s{i}")), response_code: 200 },
    );
}
for a in csm.k8s_abuse_detector().analyze_abuse("attacker") {
    eprintln!("K8S ABUSE: {}", a.description);
}

// Lateral movement
if let Some(a) = csm.lateral_movement_detector().detect_lateral_movement("pod1", "ns-a", "ns-b") {
    eprintln!("LATERAL: {} -> {}", a.source_namespace, a.target_namespace);
}

// Registry poisoning
csm.registry_poisoning_detector().register_trusted_image(
    "docker.io:nginx:latest".into(),
    "sha256:abc123".into(),
);
let _ = csm.registry_poisoning_detector().verify_image(
    "docker.io", "nginx", "latest", "sha256:malicious",
);
```

## Reporting

```rust
let report = csm.get_security_report();
// report.escape_alerts, report.k8s_abuse_alerts, ...
```

## Truthful-by-default
- Library simulates and analyzes events; it does not claim live cluster hooks.
- Evidence and descriptions reflect actual inputs provided to the APIs.

## Testing

```bash
cargo test -p container_security
```
