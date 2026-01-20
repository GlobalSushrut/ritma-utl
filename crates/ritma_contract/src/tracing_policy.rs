//! TracingPolicy Module
//!
//! Provides YAML-based custom tracing policy configuration similar to Tetragon's TracingPolicy.
//! Allows users to define custom syscall hooks, file watches, and network filters.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// TracingPolicy - defines what to trace and how
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingPolicy {
    /// Policy name
    pub name: String,
    /// Policy description
    #[serde(default)]
    pub description: String,
    /// Whether policy is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Syscall tracing rules
    #[serde(default)]
    pub syscalls: Vec<SyscallRule>,
    /// File watch rules
    #[serde(default)]
    pub file_watches: Vec<FileWatchRule>,
    /// Network rules
    #[serde(default)]
    pub network: Vec<NetworkRule>,
    /// Process rules
    #[serde(default)]
    pub process: Vec<ProcessRule>,
    /// Kubernetes selectors (optional)
    #[serde(default)]
    pub selectors: Vec<K8sSelector>,
    /// Actions to take on match
    #[serde(default)]
    pub actions: Vec<PolicyAction>,
    /// Labels to add to events
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

/// Syscall tracing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRule {
    /// Syscall name or number
    pub syscall: String,
    /// Arguments to capture
    #[serde(default)]
    pub args: Vec<ArgSpec>,
    /// Return value capture
    #[serde(default)]
    pub return_value: bool,
    /// Filters
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Severity level
    #[serde(default)]
    pub severity: Severity,
}

/// Argument specification for syscall tracing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgSpec {
    /// Argument index (0-based)
    pub index: u8,
    /// Argument type
    #[serde(rename = "type")]
    pub arg_type: ArgType,
    /// Label for the argument
    #[serde(default)]
    pub label: Option<String>,
    /// Max size for string/buffer types
    #[serde(default)]
    pub max_size: Option<usize>,
}

/// Argument types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgType {
    Int,
    Uint,
    String,
    Path,
    Buffer,
    Fd,
    Sockaddr,
    Size,
    Flags,
}

/// File watch rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWatchRule {
    /// Path pattern (glob supported)
    pub path: String,
    /// Operations to watch
    #[serde(default)]
    pub operations: Vec<FileOperation>,
    /// Whether to recurse into directories
    #[serde(default)]
    pub recursive: bool,
    /// Filters
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Severity level
    #[serde(default)]
    pub severity: Severity,
}

/// File operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Read,
    Write,
    Execute,
    Create,
    Delete,
    Rename,
    Chmod,
    Chown,
    Link,
    Truncate,
}

/// Network rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Protocol (tcp, udp, icmp, any)
    #[serde(default = "default_any")]
    pub protocol: String,
    /// Direction (ingress, egress, any)
    #[serde(default = "default_any")]
    pub direction: String,
    /// Port or port range
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    /// CIDR blocks
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// DNS patterns
    #[serde(default)]
    pub dns_patterns: Vec<String>,
    /// Filters
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Severity level
    #[serde(default)]
    pub severity: Severity,
}

fn default_any() -> String {
    "any".to_string()
}

/// Port specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Single(u16),
    Range { start: u16, end: u16 },
}

impl PortSpec {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortSpec::Single(p) => *p == port,
            PortSpec::Range { start, end } => port >= *start && port <= *end,
        }
    }
}

/// Process rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRule {
    /// Binary path pattern
    #[serde(default)]
    pub binary: Option<String>,
    /// Command line pattern
    #[serde(default)]
    pub command_line: Option<String>,
    /// User ID
    #[serde(default)]
    pub uid: Option<i64>,
    /// Events to capture
    #[serde(default)]
    pub events: Vec<ProcessEvent>,
    /// Filters
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Severity level
    #[serde(default)]
    pub severity: Severity,
}

/// Process events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessEvent {
    Exec,
    Exit,
    Fork,
    Clone,
    Setuid,
    Setgid,
    Capabilities,
}

/// Kubernetes selector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sSelector {
    /// Namespace selector
    #[serde(default)]
    pub namespace: Option<String>,
    /// Pod label selector
    #[serde(default)]
    pub pod_labels: HashMap<String, String>,
    /// Container name
    #[serde(default)]
    pub container: Option<String>,
}

/// Filter condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    /// Field to filter on
    pub field: String,
    /// Operator
    pub operator: FilterOperator,
    /// Value(s) to compare
    pub values: Vec<String>,
}

/// Filter operators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterOperator {
    Equal,
    NotEqual,
    In,
    NotIn,
    Prefix,
    Suffix,
    Contains,
    Regex,
    GreaterThan,
    LessThan,
}

impl Filter {
    /// Check if a value matches this filter
    pub fn matches(&self, value: &str) -> bool {
        match self.operator {
            FilterOperator::Equal => self.values.iter().any(|v| v == value),
            FilterOperator::NotEqual => !self.values.iter().any(|v| v == value),
            FilterOperator::In => self.values.contains(&value.to_string()),
            FilterOperator::NotIn => !self.values.contains(&value.to_string()),
            FilterOperator::Prefix => self.values.iter().any(|v| value.starts_with(v)),
            FilterOperator::Suffix => self.values.iter().any(|v| value.ends_with(v)),
            FilterOperator::Contains => self.values.iter().any(|v| value.contains(v)),
            FilterOperator::Regex => {
                // Simple pattern matching (production would use regex crate)
                self.values.iter().any(|pattern| {
                    if pattern.contains('*') {
                        let parts: Vec<&str> = pattern.split('*').collect();
                        if parts.len() == 2 {
                            value.starts_with(parts[0]) && value.ends_with(parts[1])
                        } else {
                            false
                        }
                    } else {
                        value == pattern
                    }
                })
            }
            FilterOperator::GreaterThan => {
                if let (Ok(v), Some(Ok(threshold))) = (
                    value.parse::<i64>(),
                    self.values.first().map(|s| s.parse::<i64>()),
                ) {
                    v > threshold
                } else {
                    false
                }
            }
            FilterOperator::LessThan => {
                if let (Ok(v), Some(Ok(threshold))) = (
                    value.parse::<i64>(),
                    self.values.first().map(|s| s.parse::<i64>()),
                ) {
                    v < threshold
                } else {
                    false
                }
            }
        }
    }
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Log the event
    Log,
    /// Generate alert
    Alert,
    /// Block/deny (requires enforcement mode)
    Deny,
    /// Kill the process (requires enforcement mode)
    Kill,
    /// Throttle/rate limit
    Throttle,
    /// Override severity
    Override { severity: Severity },
    /// Add custom label
    Label { key: String, value: String },
}

/// Severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_score(&self) -> f64 {
        match self {
            Severity::Info => 0.0,
            Severity::Low => 2.5,
            Severity::Medium => 5.0,
            Severity::High => 7.5,
            Severity::Critical => 10.0,
        }
    }
}

/// Policy manager - loads and evaluates policies
pub struct PolicyManager {
    policies: Vec<TracingPolicy>,
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyManager {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Load policy from YAML string
    pub fn load_yaml(&mut self, yaml: &str) -> Result<(), String> {
        let policy: TracingPolicy =
            serde_yaml::from_str(yaml).map_err(|e| format!("YAML parse error: {}", e))?;
        self.policies.push(policy);
        Ok(())
    }

    /// Load policy from file
    pub fn load_file(&mut self, path: &Path) -> Result<(), String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("File read error: {}", e))?;
        self.load_yaml(&content)
    }

    /// Load all policies from directory
    pub fn load_directory(&mut self, dir: &Path) -> Result<usize, String> {
        let mut count = 0;
        if !dir.exists() {
            return Ok(0);
        }

        let entries = std::fs::read_dir(dir).map_err(|e| format!("Dir read error: {}", e))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .map(|e| e == "yaml" || e == "yml")
                .unwrap_or(false)
            {
                if let Err(e) = self.load_file(&path) {
                    eprintln!("Warning: failed to load policy {:?}: {}", path, e);
                } else {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Get all enabled policies
    pub fn enabled_policies(&self) -> impl Iterator<Item = &TracingPolicy> {
        self.policies.iter().filter(|p| p.enabled)
    }

    /// Check if a syscall should be traced
    pub fn should_trace_syscall(
        &self,
        syscall: &str,
        context: &EventContext,
    ) -> Option<&SyscallRule> {
        for policy in self.enabled_policies() {
            if !self.matches_selectors(&policy.selectors, context) {
                continue;
            }

            for rule in &policy.syscalls {
                if rule.syscall == syscall || rule.syscall == "*" {
                    if self.matches_filters(&rule.filters, context) {
                        return Some(rule);
                    }
                }
            }
        }
        None
    }

    /// Check if a file access should be traced
    pub fn should_trace_file(
        &self,
        path: &str,
        op: FileOperation,
        context: &EventContext,
    ) -> Option<&FileWatchRule> {
        for policy in self.enabled_policies() {
            if !self.matches_selectors(&policy.selectors, context) {
                continue;
            }

            for rule in &policy.file_watches {
                if self.path_matches(&rule.path, path) {
                    if rule.operations.is_empty() || rule.operations.contains(&op) {
                        if self.matches_filters(&rule.filters, context) {
                            return Some(rule);
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if network activity should be traced
    pub fn should_trace_network(
        &self,
        protocol: &str,
        direction: &str,
        port: u16,
        addr: &str,
        context: &EventContext,
    ) -> Option<&NetworkRule> {
        for policy in self.enabled_policies() {
            if !self.matches_selectors(&policy.selectors, context) {
                continue;
            }

            for rule in &policy.network {
                // Check protocol
                if rule.protocol != "any" && rule.protocol != protocol {
                    continue;
                }

                // Check direction
                if rule.direction != "any" && rule.direction != direction {
                    continue;
                }

                // Check ports
                if !rule.ports.is_empty() && !rule.ports.iter().any(|p| p.matches(port)) {
                    continue;
                }

                // Check CIDRs (simplified - production would use proper CIDR matching)
                if !rule.cidrs.is_empty() {
                    let matches_cidr = rule.cidrs.iter().any(|cidr| {
                        if cidr.contains('/') {
                            // Simple prefix match for now
                            let prefix = cidr.split('/').next().unwrap_or("");
                            addr.starts_with(
                                prefix
                                    .split('.')
                                    .take(2)
                                    .collect::<Vec<_>>()
                                    .join(".")
                                    .as_str(),
                            )
                        } else {
                            addr == cidr
                        }
                    });
                    if !matches_cidr {
                        continue;
                    }
                }

                if self.matches_filters(&rule.filters, context) {
                    return Some(rule);
                }
            }
        }
        None
    }

    /// Check if process event should be traced
    pub fn should_trace_process(
        &self,
        event: ProcessEvent,
        context: &EventContext,
    ) -> Option<&ProcessRule> {
        for policy in self.enabled_policies() {
            if !self.matches_selectors(&policy.selectors, context) {
                continue;
            }

            for rule in &policy.process {
                // Check binary pattern
                if let Some(ref binary) = rule.binary {
                    if let Some(ref exe) = context.exe {
                        if !self.path_matches(binary, exe) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                // Check command line pattern
                if let Some(ref cmd_pattern) = rule.command_line {
                    if let Some(ref cmd) = context.command_line {
                        if !cmd.contains(cmd_pattern) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                // Check UID
                if let Some(uid) = rule.uid {
                    if context.uid != Some(uid) {
                        continue;
                    }
                }

                // Check event type
                if !rule.events.is_empty() && !rule.events.contains(&event) {
                    continue;
                }

                if self.matches_filters(&rule.filters, context) {
                    return Some(rule);
                }
            }
        }
        None
    }

    fn matches_selectors(&self, selectors: &[K8sSelector], context: &EventContext) -> bool {
        if selectors.is_empty() {
            return true;
        }

        for selector in selectors {
            let mut matches = true;

            if let Some(ref ns) = selector.namespace {
                if context.k8s_namespace.as_ref() != Some(ns) {
                    matches = false;
                }
            }

            if !selector.pod_labels.is_empty() {
                if let Some(ref labels) = context.k8s_labels {
                    for (key, value) in &selector.pod_labels {
                        if labels.get(key) != Some(value) {
                            matches = false;
                            break;
                        }
                    }
                } else {
                    matches = false;
                }
            }

            if let Some(ref container) = selector.container {
                if context.container_name.as_ref() != Some(container) {
                    matches = false;
                }
            }

            if matches {
                return true;
            }
        }

        false
    }

    fn matches_filters(&self, filters: &[Filter], context: &EventContext) -> bool {
        for filter in filters {
            let value = match filter.field.as_str() {
                "pid" => context.pid.map(|p| p.to_string()),
                "uid" => context.uid.map(|u| u.to_string()),
                "exe" => context.exe.clone(),
                "comm" => context.comm.clone(),
                "container_id" => context.container_id.clone(),
                "k8s_namespace" => context.k8s_namespace.clone(),
                "k8s_pod" => context.k8s_pod.clone(),
                _ => None,
            };

            if let Some(v) = value {
                if !filter.matches(&v) {
                    return false;
                }
            }
        }
        true
    }

    fn path_matches(&self, pattern: &str, path: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern.contains('*') {
            // Simple glob matching
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                return path.starts_with(parts[0]) && path.ends_with(parts[1]);
            }
        }

        path == pattern || path.starts_with(&format!("{}/", pattern))
    }
}

/// Event context for policy evaluation
#[derive(Debug, Clone, Default)]
pub struct EventContext {
    pub pid: Option<i64>,
    pub ppid: Option<i64>,
    pub uid: Option<i64>,
    pub gid: Option<i64>,
    pub exe: Option<String>,
    pub comm: Option<String>,
    pub command_line: Option<String>,
    pub container_id: Option<String>,
    pub container_name: Option<String>,
    pub k8s_namespace: Option<String>,
    pub k8s_pod: Option<String>,
    pub k8s_labels: Option<HashMap<String, String>>,
}

/// Built-in policy templates
pub fn builtin_policies() -> Vec<TracingPolicy> {
    vec![
        // Sensitive file access policy
        TracingPolicy {
            name: "sensitive-files".to_string(),
            description: "Monitor access to sensitive files".to_string(),
            enabled: true,
            syscalls: Vec::new(),
            file_watches: vec![
                FileWatchRule {
                    path: "/etc/passwd".to_string(),
                    operations: vec![FileOperation::Read, FileOperation::Write],
                    recursive: false,
                    filters: Vec::new(),
                    severity: Severity::Medium,
                },
                FileWatchRule {
                    path: "/etc/shadow".to_string(),
                    operations: vec![FileOperation::Read, FileOperation::Write],
                    recursive: false,
                    filters: Vec::new(),
                    severity: Severity::High,
                },
                FileWatchRule {
                    path: "/etc/sudoers*".to_string(),
                    operations: vec![FileOperation::Read, FileOperation::Write],
                    recursive: false,
                    filters: Vec::new(),
                    severity: Severity::High,
                },
                FileWatchRule {
                    path: "/root/.ssh/*".to_string(),
                    operations: vec![
                        FileOperation::Read,
                        FileOperation::Write,
                        FileOperation::Create,
                    ],
                    recursive: true,
                    filters: Vec::new(),
                    severity: Severity::Critical,
                },
            ],
            network: Vec::new(),
            process: Vec::new(),
            selectors: Vec::new(),
            actions: vec![PolicyAction::Log, PolicyAction::Alert],
            labels: HashMap::new(),
        },
        // Privilege escalation policy
        TracingPolicy {
            name: "privilege-escalation".to_string(),
            description: "Detect privilege escalation attempts".to_string(),
            enabled: true,
            syscalls: vec![
                SyscallRule {
                    syscall: "setuid".to_string(),
                    args: vec![ArgSpec {
                        index: 0,
                        arg_type: ArgType::Uint,
                        label: Some("new_uid".to_string()),
                        max_size: None,
                    }],
                    return_value: true,
                    filters: Vec::new(),
                    severity: Severity::High,
                },
                SyscallRule {
                    syscall: "setgid".to_string(),
                    args: vec![ArgSpec {
                        index: 0,
                        arg_type: ArgType::Uint,
                        label: Some("new_gid".to_string()),
                        max_size: None,
                    }],
                    return_value: true,
                    filters: Vec::new(),
                    severity: Severity::High,
                },
            ],
            file_watches: Vec::new(),
            network: Vec::new(),
            process: vec![ProcessRule {
                binary: Some("/usr/bin/sudo".to_string()),
                command_line: None,
                uid: None,
                events: vec![ProcessEvent::Exec],
                filters: Vec::new(),
                severity: Severity::Medium,
            }],
            selectors: Vec::new(),
            actions: vec![PolicyAction::Log, PolicyAction::Alert],
            labels: HashMap::new(),
        },
        // Network exfiltration policy
        TracingPolicy {
            name: "network-exfiltration".to_string(),
            description: "Detect potential data exfiltration".to_string(),
            enabled: true,
            syscalls: Vec::new(),
            file_watches: Vec::new(),
            network: vec![
                NetworkRule {
                    protocol: "tcp".to_string(),
                    direction: "egress".to_string(),
                    ports: vec![
                        PortSpec::Single(22),
                        PortSpec::Single(21),
                        PortSpec::Range {
                            start: 4000,
                            end: 5000,
                        },
                    ],
                    cidrs: Vec::new(),
                    dns_patterns: Vec::new(),
                    filters: Vec::new(),
                    severity: Severity::Medium,
                },
                NetworkRule {
                    protocol: "any".to_string(),
                    direction: "egress".to_string(),
                    ports: Vec::new(),
                    cidrs: Vec::new(),
                    dns_patterns: vec!["*.onion".to_string(), "*.tor".to_string()],
                    filters: Vec::new(),
                    severity: Severity::Critical,
                },
            ],
            process: Vec::new(),
            selectors: Vec::new(),
            actions: vec![PolicyAction::Log, PolicyAction::Alert],
            labels: HashMap::new(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_yaml_parsing() {
        let yaml = r#"
name: test-policy
description: Test policy
enabled: true
syscalls:
  - syscall: execve
    args:
      - index: 0
        type: path
        label: filename
    return_value: true
    severity: medium
file_watches:
  - path: /etc/passwd
    operations: [read, write]
    severity: high
network:
  - protocol: tcp
    direction: egress
    ports:
      - 443
      - start: 8000
        end: 9000
    severity: low
"#;

        let policy: TracingPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.name, "test-policy");
        assert!(policy.enabled);
        assert_eq!(policy.syscalls.len(), 1);
        assert_eq!(policy.file_watches.len(), 1);
        assert_eq!(policy.network.len(), 1);
    }

    #[test]
    fn test_filter_matching() {
        let filter = Filter {
            field: "uid".to_string(),
            operator: FilterOperator::Equal,
            values: vec!["1000".to_string()],
        };
        assert!(filter.matches("1000"));
        assert!(!filter.matches("0"));

        let prefix_filter = Filter {
            field: "path".to_string(),
            operator: FilterOperator::Prefix,
            values: vec!["/etc/".to_string()],
        };
        assert!(prefix_filter.matches("/etc/passwd"));
        assert!(!prefix_filter.matches("/var/log/test"));
    }

    #[test]
    fn test_port_spec_matching() {
        let single = PortSpec::Single(443);
        assert!(single.matches(443));
        assert!(!single.matches(80));

        let range = PortSpec::Range {
            start: 8000,
            end: 9000,
        };
        assert!(range.matches(8500));
        assert!(!range.matches(7999));
        assert!(!range.matches(9001));
    }

    #[test]
    fn test_policy_manager() {
        let mut manager = PolicyManager::new();

        let yaml = r#"
name: test
enabled: true
file_watches:
  - path: /etc/*
    operations: [read]
    severity: medium
"#;
        manager.load_yaml(yaml).unwrap();

        let context = EventContext::default();
        let rule = manager.should_trace_file("/etc/passwd", FileOperation::Read, &context);
        assert!(rule.is_some());

        let rule2 = manager.should_trace_file("/var/log/test", FileOperation::Read, &context);
        assert!(rule2.is_none());
    }

    #[test]
    fn test_builtin_policies() {
        let policies = builtin_policies();
        assert!(!policies.is_empty());

        for policy in &policies {
            assert!(!policy.name.is_empty());
            assert!(policy.enabled);
        }
    }
}
