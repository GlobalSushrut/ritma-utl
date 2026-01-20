//! SIEM Export Module
//!
//! Provides export formats for Security Information and Event Management (SIEM) systems.
//! Supports JSON, CEF (Common Event Format), LEEF (Log Event Extended Format),
//! and Syslog formats for integration with Splunk, Elastic, Microsoft Sentinel, etc.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;

/// SIEM export format
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiemFormat {
    /// JSON Lines format (one JSON object per line)
    JsonLines,
    /// Common Event Format (ArcSight, Splunk)
    CEF,
    /// Log Event Extended Format (IBM QRadar)
    LEEF,
    /// Syslog RFC 5424
    Syslog,
    /// Elastic Common Schema (ECS)
    ECS,
    /// Open Cybersecurity Schema Framework (OCSF)
    OCSF,
}

/// Severity level for SIEM events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiemSeverity {
    Unknown = 0,
    Low = 1,
    Medium = 4,
    High = 7,
    Critical = 10,
}

impl SiemSeverity {
    pub fn from_score(score: f64) -> Self {
        if score >= 9.0 {
            SiemSeverity::Critical
        } else if score >= 7.0 {
            SiemSeverity::High
        } else if score >= 4.0 {
            SiemSeverity::Medium
        } else if score >= 1.0 {
            SiemSeverity::Low
        } else {
            SiemSeverity::Unknown
        }
    }

    pub fn as_cef(&self) -> u8 {
        *self as u8
    }

    pub fn as_string(&self) -> &'static str {
        match self {
            SiemSeverity::Unknown => "unknown",
            SiemSeverity::Low => "low",
            SiemSeverity::Medium => "medium",
            SiemSeverity::High => "high",
            SiemSeverity::Critical => "critical",
        }
    }
}

/// SIEM Event - normalized event for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    /// Event timestamp (ISO 8601)
    pub timestamp: String,
    /// Event ID
    pub event_id: String,
    /// Event type/category
    pub event_type: String,
    /// Event action
    pub action: String,
    /// Outcome (success, failure, unknown)
    pub outcome: String,
    /// Severity
    pub severity: SiemSeverity,
    /// Source host
    pub src_host: Option<String>,
    /// Source IP
    pub src_ip: Option<String>,
    /// Source port
    pub src_port: Option<u16>,
    /// Destination host
    pub dst_host: Option<String>,
    /// Destination IP
    pub dst_ip: Option<String>,
    /// Destination port
    pub dst_port: Option<u16>,
    /// Process ID
    pub pid: Option<i64>,
    /// Parent process ID
    pub ppid: Option<i64>,
    /// User ID
    pub uid: Option<i64>,
    /// Username
    pub user: Option<String>,
    /// Process name
    pub process_name: Option<String>,
    /// Process command line
    pub command_line: Option<String>,
    /// File path
    pub file_path: Option<String>,
    /// File hash
    pub file_hash: Option<String>,
    /// Container ID
    pub container_id: Option<String>,
    /// Kubernetes namespace
    pub k8s_namespace: Option<String>,
    /// Kubernetes pod name
    pub k8s_pod: Option<String>,
    /// Message/description
    pub message: Option<String>,
    /// Additional fields
    pub extensions: HashMap<String, String>,
}

impl Default for SiemEvent {
    fn default() -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_id: String::new(),
            event_type: String::new(),
            action: String::new(),
            outcome: "unknown".to_string(),
            severity: SiemSeverity::Unknown,
            src_host: None,
            src_ip: None,
            src_port: None,
            dst_host: None,
            dst_ip: None,
            dst_port: None,
            pid: None,
            ppid: None,
            uid: None,
            user: None,
            process_name: None,
            command_line: None,
            file_path: None,
            file_hash: None,
            container_id: None,
            k8s_namespace: None,
            k8s_pod: None,
            message: None,
            extensions: HashMap::new(),
        }
    }
}

/// CEF (Common Event Format) exporter
/// Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
pub struct CefExporter {
    vendor: String,
    product: String,
    version: String,
}

impl Default for CefExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl CefExporter {
    pub fn new() -> Self {
        Self {
            vendor: "Ritma".to_string(),
            product: "CCTV".to_string(),
            version: "1.0".to_string(),
        }
    }

    pub fn with_config(vendor: String, product: String, version: String) -> Self {
        Self {
            vendor,
            product,
            version,
        }
    }

    /// Escape CEF special characters
    fn escape_header(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('|', "\\|")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    /// Escape CEF extension value
    fn escape_extension(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    /// Export event to CEF format
    pub fn export(&self, event: &SiemEvent) -> String {
        let mut extensions = Vec::new();

        // Standard CEF extensions
        extensions.push(format!("rt={}", event.timestamp));

        if let Some(ref src_ip) = event.src_ip {
            extensions.push(format!("src={}", src_ip));
        }
        if let Some(src_port) = event.src_port {
            extensions.push(format!("spt={}", src_port));
        }
        if let Some(ref dst_ip) = event.dst_ip {
            extensions.push(format!("dst={}", dst_ip));
        }
        if let Some(dst_port) = event.dst_port {
            extensions.push(format!("dpt={}", dst_port));
        }
        if let Some(ref src_host) = event.src_host {
            extensions.push(format!("shost={}", Self::escape_extension(src_host)));
        }
        if let Some(ref dst_host) = event.dst_host {
            extensions.push(format!("dhost={}", Self::escape_extension(dst_host)));
        }
        if let Some(pid) = event.pid {
            extensions.push(format!("spid={}", pid));
        }
        if let Some(ppid) = event.ppid {
            extensions.push(format!("sproc={}", ppid));
        }
        if let Some(uid) = event.uid {
            extensions.push(format!("suid={}", uid));
        }
        if let Some(ref user) = event.user {
            extensions.push(format!("suser={}", Self::escape_extension(user)));
        }
        if let Some(ref process_name) = event.process_name {
            extensions.push(format!("sproc={}", Self::escape_extension(process_name)));
        }
        if let Some(ref command_line) = event.command_line {
            extensions.push(format!("cs1={}", Self::escape_extension(command_line)));
            extensions.push("cs1Label=CommandLine".to_string());
        }
        if let Some(ref file_path) = event.file_path {
            extensions.push(format!("filePath={}", Self::escape_extension(file_path)));
        }
        if let Some(ref file_hash) = event.file_hash {
            extensions.push(format!("fileHash={}", file_hash));
        }
        if let Some(ref container_id) = event.container_id {
            extensions.push(format!("cs2={}", container_id));
            extensions.push("cs2Label=ContainerID".to_string());
        }
        if let Some(ref k8s_namespace) = event.k8s_namespace {
            extensions.push(format!("cs3={}", Self::escape_extension(k8s_namespace)));
            extensions.push("cs3Label=K8sNamespace".to_string());
        }
        if let Some(ref k8s_pod) = event.k8s_pod {
            extensions.push(format!("cs4={}", Self::escape_extension(k8s_pod)));
            extensions.push("cs4Label=K8sPod".to_string());
        }
        if let Some(ref message) = event.message {
            extensions.push(format!("msg={}", Self::escape_extension(message)));
        }

        // Custom extensions
        for (key, value) in &event.extensions {
            extensions.push(format!("{}={}", key, Self::escape_extension(value)));
        }

        format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            Self::escape_header(&self.vendor),
            Self::escape_header(&self.product),
            Self::escape_header(&self.version),
            Self::escape_header(&event.event_id),
            Self::escape_header(&event.event_type),
            event.severity.as_cef(),
            extensions.join(" ")
        )
    }
}

/// LEEF (Log Event Extended Format) exporter for IBM QRadar
/// Format: LEEF:Version|Vendor|Product|Version|EventID|Extension
pub struct LeefExporter {
    vendor: String,
    product: String,
    version: String,
}

impl Default for LeefExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl LeefExporter {
    pub fn new() -> Self {
        Self {
            vendor: "Ritma".to_string(),
            product: "CCTV".to_string(),
            version: "1.0".to_string(),
        }
    }

    /// Export event to LEEF format
    pub fn export(&self, event: &SiemEvent) -> String {
        let mut extensions = Vec::new();

        extensions.push(format!("devTime={}", event.timestamp));
        extensions.push(format!("cat={}", event.event_type));
        extensions.push(format!("sev={}", event.severity.as_cef()));

        if let Some(ref src_ip) = event.src_ip {
            extensions.push(format!("src={}", src_ip));
        }
        if let Some(src_port) = event.src_port {
            extensions.push(format!("srcPort={}", src_port));
        }
        if let Some(ref dst_ip) = event.dst_ip {
            extensions.push(format!("dst={}", dst_ip));
        }
        if let Some(dst_port) = event.dst_port {
            extensions.push(format!("dstPort={}", dst_port));
        }
        if let Some(pid) = event.pid {
            extensions.push(format!("pid={}", pid));
        }
        if let Some(uid) = event.uid {
            extensions.push(format!("usrName={}", uid));
        }
        if let Some(ref process_name) = event.process_name {
            extensions.push(format!("procName={}", process_name));
        }
        if let Some(ref file_path) = event.file_path {
            extensions.push(format!("resource={}", file_path));
        }

        format!(
            "LEEF:2.0|{}|{}|{}|{}|{}",
            self.vendor,
            self.product,
            self.version,
            event.event_id,
            extensions.join("\t")
        )
    }
}

/// Elastic Common Schema (ECS) exporter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsEvent {
    #[serde(rename = "@timestamp")]
    pub timestamp: String,
    pub event: EcsEventFields,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<EcsSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<EcsDestination>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<EcsProcess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<EcsUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<EcsFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<EcsContainer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orchestrator: Option<EcsOrchestrator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsEventFields {
    pub id: String,
    pub kind: String,
    pub category: Vec<String>,
    #[serde(rename = "type")]
    pub event_type: Vec<String>,
    pub action: String,
    pub outcome: String,
    pub severity: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsDestination {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsProcess {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<Box<EcsProcess>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<EcsFileHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsFileHash {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsContainer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsOrchestrator {
    #[serde(rename = "type")]
    pub orchestrator_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<EcsOrchestratorResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsOrchestratorResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub name: String,
}

/// ECS Exporter
pub struct EcsExporter;

impl Default for EcsExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl EcsExporter {
    pub fn new() -> Self {
        Self
    }

    /// Convert SiemEvent to ECS format
    pub fn export(&self, event: &SiemEvent) -> EcsEvent {
        let category = match event.event_type.as_str() {
            "process" | "ProcExec" => vec!["process".to_string()],
            "file" | "FileOpen" => vec!["file".to_string()],
            "network" | "NetConnect" => vec!["network".to_string()],
            "authentication" | "PrivChange" => vec!["authentication".to_string()],
            _ => vec!["host".to_string()],
        };

        EcsEvent {
            timestamp: event.timestamp.clone(),
            event: EcsEventFields {
                id: event.event_id.clone(),
                kind: "event".to_string(),
                category,
                event_type: vec![event.action.clone()],
                action: event.action.clone(),
                outcome: event.outcome.clone(),
                severity: event.severity.as_cef(),
            },
            source: if event.src_ip.is_some() || event.src_port.is_some() {
                Some(EcsSource {
                    ip: event.src_ip.clone(),
                    port: event.src_port,
                    domain: event.src_host.clone(),
                })
            } else {
                None
            },
            destination: if event.dst_ip.is_some() || event.dst_port.is_some() {
                Some(EcsDestination {
                    ip: event.dst_ip.clone(),
                    port: event.dst_port,
                    domain: event.dst_host.clone(),
                })
            } else {
                None
            },
            process: if event.pid.is_some() || event.process_name.is_some() {
                Some(EcsProcess {
                    pid: event.pid,
                    name: event.process_name.clone(),
                    command_line: event.command_line.clone(),
                    parent: event.ppid.map(|ppid| {
                        Box::new(EcsProcess {
                            pid: Some(ppid),
                            name: None,
                            command_line: None,
                            parent: None,
                        })
                    }),
                })
            } else {
                None
            },
            user: if event.uid.is_some() || event.user.is_some() {
                Some(EcsUser {
                    id: event.uid.map(|u| u.to_string()),
                    name: event.user.clone(),
                })
            } else {
                None
            },
            file: if event.file_path.is_some() || event.file_hash.is_some() {
                Some(EcsFile {
                    path: event.file_path.clone(),
                    hash: event.file_hash.as_ref().map(|h| EcsFileHash {
                        sha256: Some(h.clone()),
                    }),
                })
            } else {
                None
            },
            container: event.container_id.as_ref().map(|id| EcsContainer {
                id: Some(id.clone()),
                name: None,
            }),
            orchestrator: event.k8s_namespace.as_ref().map(|ns| EcsOrchestrator {
                orchestrator_type: "kubernetes".to_string(),
                namespace: Some(ns.clone()),
                resource: event.k8s_pod.as_ref().map(|pod| EcsOrchestratorResource {
                    resource_type: "pod".to_string(),
                    name: pod.clone(),
                }),
            }),
            message: event.message.clone(),
            labels: event.extensions.clone(),
        }
    }

    /// Export to JSON string
    pub fn export_json(&self, event: &SiemEvent) -> Result<String, serde_json::Error> {
        let ecs = self.export(event);
        serde_json::to_string(&ecs)
    }
}

/// Syslog RFC 5424 exporter
pub struct SyslogExporter {
    app_name: String,
    hostname: String,
}

impl Default for SyslogExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl SyslogExporter {
    pub fn new() -> Self {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "ritma".to_string());

        Self {
            app_name: "ritma-cctv".to_string(),
            hostname,
        }
    }

    /// Map severity to syslog priority
    fn severity_to_priority(&self, severity: SiemSeverity) -> u8 {
        // Facility: local0 (16), Severity: based on event
        let facility = 16u8;
        let sev = match severity {
            SiemSeverity::Critical => 2, // Critical
            SiemSeverity::High => 3,     // Error
            SiemSeverity::Medium => 4,   // Warning
            SiemSeverity::Low => 5,      // Notice
            SiemSeverity::Unknown => 6,  // Informational
        };
        facility * 8 + sev
    }

    /// Export to RFC 5424 syslog format
    pub fn export(&self, event: &SiemEvent) -> String {
        let priority = self.severity_to_priority(event.severity);
        let version = 1;
        let timestamp = &event.timestamp;
        let msgid = &event.event_id;

        // Structured data
        let mut sd = String::new();
        sd.push_str(&format!(
            "[ritma@12345 eventType=\"{}\" action=\"{}\" outcome=\"{}\"]",
            event.event_type, event.action, event.outcome
        ));

        if let Some(ref pid) = event.pid {
            sd.push_str(&format!("[process@12345 pid=\"{}\"]", pid));
        }

        let message = event.message.as_deref().unwrap_or("-");

        format!(
            "<{}>{} {} {} {} {} {} {} {}",
            priority,
            version,
            timestamp,
            self.hostname,
            self.app_name,
            event.pid.unwrap_or(0),
            msgid,
            sd,
            message
        )
    }
}

/// SIEM Export Writer
/// Writes events to file or stream in specified format
pub struct SiemExportWriter<W: Write> {
    writer: W,
    format: SiemFormat,
    cef_exporter: CefExporter,
    leef_exporter: LeefExporter,
    ecs_exporter: EcsExporter,
    syslog_exporter: SyslogExporter,
}

impl<W: Write> SiemExportWriter<W> {
    pub fn new(writer: W, format: SiemFormat) -> Self {
        Self {
            writer,
            format,
            cef_exporter: CefExporter::new(),
            leef_exporter: LeefExporter::new(),
            ecs_exporter: EcsExporter::new(),
            syslog_exporter: SyslogExporter::new(),
        }
    }

    /// Write a single event
    pub fn write_event(&mut self, event: &SiemEvent) -> std::io::Result<()> {
        let line = match self.format {
            SiemFormat::JsonLines => serde_json::to_string(event)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            SiemFormat::CEF => self.cef_exporter.export(event),
            SiemFormat::LEEF => self.leef_exporter.export(event),
            SiemFormat::ECS => self
                .ecs_exporter
                .export_json(event)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            SiemFormat::Syslog => self.syslog_exporter.export(event),
            SiemFormat::OCSF => serde_json::to_string(event)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        };

        writeln!(self.writer, "{}", line)
    }

    /// Flush the writer
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> SiemEvent {
        SiemEvent {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            event_id: "evt_12345".to_string(),
            event_type: "process".to_string(),
            action: "start".to_string(),
            outcome: "success".to_string(),
            severity: SiemSeverity::Medium,
            src_ip: Some("192.168.1.100".to_string()),
            dst_ip: Some("10.0.0.1".to_string()),
            dst_port: Some(443),
            pid: Some(1234),
            ppid: Some(1),
            uid: Some(1000),
            process_name: Some("curl".to_string()),
            command_line: Some("curl https://api.example.com".to_string()),
            container_id: Some("abc123".to_string()),
            k8s_namespace: Some("production".to_string()),
            k8s_pod: Some("api-server-xyz".to_string()),
            message: Some("Process started".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_cef_export() {
        let exporter = CefExporter::new();
        let event = sample_event();
        let cef = exporter.export(&event);

        assert!(cef.starts_with("CEF:0|Ritma|CCTV|1.0|"));
        assert!(cef.contains("src=192.168.1.100"));
        assert!(cef.contains("dst=10.0.0.1"));
        assert!(cef.contains("dpt=443"));
        assert!(cef.contains("spid=1234"));
    }

    #[test]
    fn test_leef_export() {
        let exporter = LeefExporter::new();
        let event = sample_event();
        let leef = exporter.export(&event);

        assert!(leef.starts_with("LEEF:2.0|Ritma|CCTV|1.0|"));
        assert!(leef.contains("src=192.168.1.100"));
        assert!(leef.contains("dst=10.0.0.1"));
    }

    #[test]
    fn test_ecs_export() {
        let exporter = EcsExporter::new();
        let event = sample_event();
        let ecs = exporter.export(&event);

        assert_eq!(ecs.event.id, "evt_12345");
        assert!(ecs.process.is_some());
        assert!(ecs.container.is_some());
        assert!(ecs.orchestrator.is_some());
    }

    #[test]
    fn test_syslog_export() {
        let exporter = SyslogExporter::new();
        let event = sample_event();
        let syslog = exporter.export(&event);

        assert!(syslog.contains("ritma-cctv"));
        assert!(syslog.contains("evt_12345"));
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(SiemSeverity::from_score(9.5), SiemSeverity::Critical);
        assert_eq!(SiemSeverity::from_score(7.5), SiemSeverity::High);
        assert_eq!(SiemSeverity::from_score(5.0), SiemSeverity::Medium);
        assert_eq!(SiemSeverity::from_score(2.0), SiemSeverity::Low);
        assert_eq!(SiemSeverity::from_score(0.0), SiemSeverity::Unknown);
    }

    #[test]
    fn test_writer() {
        let mut buffer = Vec::new();
        let event = sample_event();

        {
            let mut writer = SiemExportWriter::new(&mut buffer, SiemFormat::JsonLines);
            writer.write_event(&event).unwrap();
            writer.flush().unwrap();
        }

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("evt_12345"));
        assert!(output.contains("192.168.1.100"));
    }
}
