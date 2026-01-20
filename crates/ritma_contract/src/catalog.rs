//! Daily catalog (2.8)
//!
//! This module defines the daily catalog format with per-window summaries,
//! sketches for top processes, top outbound IPs, anomaly scores, and event counts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Per-window summary in the daily catalog
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSummary {
    pub start_ts: i64,
    pub end_ts: i64,
    pub host_id: String,
    pub boot_id: Option<String>,
    pub event_count: u64,
    pub micro_root: [u8; 32],
    pub hour_root: Option<[u8; 32]>,
    pub rule_triggers: Vec<String>,
}

impl WindowSummary {
    pub fn new(
        start_ts: i64,
        end_ts: i64,
        host_id: &str,
        event_count: u64,
        micro_root: [u8; 32],
    ) -> Self {
        Self {
            start_ts,
            end_ts,
            host_id: host_id.to_string(),
            boot_id: None,
            event_count,
            micro_root,
            hour_root: None,
            rule_triggers: Vec::new(),
        }
    }

    pub fn with_boot_id(mut self, boot_id: &str) -> Self {
        self.boot_id = Some(boot_id.to_string());
        self
    }

    pub fn with_hour_root(mut self, root: [u8; 32]) -> Self {
        self.hour_root = Some(root);
        self
    }

    pub fn add_rule_trigger(&mut self, rule: &str) {
        self.rule_triggers.push(rule.to_string());
    }
}

/// Top-N sketch entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopEntry {
    pub key: String,
    pub count: u64,
}

impl TopEntry {
    pub fn new(key: &str, count: u64) -> Self {
        Self {
            key: key.to_string(),
            count,
        }
    }
}

/// Event type counts
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventTypeCounts {
    pub proc_exec: u64,
    pub proc_exit: u64,
    pub file_open: u64,
    pub file_write: u64,
    pub net_connect: u64,
    pub net_accept: u64,
    pub dns_query: u64,
    pub auth: u64,
    pub other: u64,
}

impl EventTypeCounts {
    pub fn total(&self) -> u64 {
        self.proc_exec
            + self.proc_exit
            + self.file_open
            + self.file_write
            + self.net_connect
            + self.net_accept
            + self.dns_query
            + self.auth
            + self.other
    }

    pub fn increment(&mut self, event_type: &str) {
        match event_type {
            "proc_exec" => self.proc_exec += 1,
            "proc_exit" => self.proc_exit += 1,
            "file_open" => self.file_open += 1,
            "file_write" => self.file_write += 1,
            "net_connect" => self.net_connect += 1,
            "net_accept" => self.net_accept += 1,
            "dns_query" => self.dns_query += 1,
            "auth" => self.auth += 1,
            _ => self.other += 1,
        }
    }
}

/// Daily catalog sketches
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DailySketches {
    pub top_processes: Vec<TopEntry>,
    pub top_outbound_ips: Vec<TopEntry>,
    pub top_files: Vec<TopEntry>,
    pub top_users: Vec<TopEntry>,
    pub event_counts: EventTypeCounts,
    pub anomaly_score: f64,
    pub alert_count: u32,
}

impl DailySketches {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_top_processes(&mut self, entries: Vec<TopEntry>) {
        self.top_processes = entries;
    }

    pub fn set_top_outbound_ips(&mut self, entries: Vec<TopEntry>) {
        self.top_outbound_ips = entries;
    }

    pub fn set_top_files(&mut self, entries: Vec<TopEntry>) {
        self.top_files = entries;
    }

    pub fn set_top_users(&mut self, entries: Vec<TopEntry>) {
        self.top_users = entries;
    }

    pub fn set_anomaly_score(&mut self, score: f64) {
        self.anomaly_score = score;
    }

    pub fn increment_alerts(&mut self) {
        self.alert_count += 1;
    }
}

/// Daily catalog entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyCatalog {
    pub date: String, // YYYY-MM-DD
    pub node_id: String,
    pub window_summaries: Vec<WindowSummary>,
    pub sketches: DailySketches,
    pub total_events: u64,
    pub total_windows: u32,
    pub created_ts: i64,
}

impl DailyCatalog {
    pub fn new(date: &str, node_id: &str) -> Self {
        Self {
            date: date.to_string(),
            node_id: node_id.to_string(),
            window_summaries: Vec::new(),
            sketches: DailySketches::new(),
            total_events: 0,
            total_windows: 0,
            created_ts: chrono::Utc::now().timestamp(),
        }
    }

    pub fn add_window(&mut self, summary: WindowSummary) {
        self.total_events += summary.event_count;
        self.total_windows += 1;
        self.window_summaries.push(summary);
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let summaries: Vec<_> = self
            .window_summaries
            .iter()
            .map(|s| {
                (
                    s.start_ts,
                    s.end_ts,
                    &s.host_id,
                    s.boot_id.as_deref(),
                    s.event_count,
                    hex::encode(s.micro_root),
                    s.hour_root.map(hex::encode),
                    &s.rule_triggers,
                )
            })
            .collect();

        let sketches = (
            &self.sketches.top_processes,
            &self.sketches.top_outbound_ips,
            &self.sketches.top_files,
            &self.sketches.top_users,
            (
                self.sketches.event_counts.proc_exec,
                self.sketches.event_counts.proc_exit,
                self.sketches.event_counts.file_open,
                self.sketches.event_counts.file_write,
                self.sketches.event_counts.net_connect,
                self.sketches.event_counts.net_accept,
                self.sketches.event_counts.dns_query,
                self.sketches.event_counts.auth,
                self.sketches.event_counts.other,
            ),
            self.sketches.anomaly_score,
            self.sketches.alert_count,
        );

        let tuple = (
            "ritma-catalog@0.3",
            &self.date,
            &self.node_id,
            self.total_events,
            self.total_windows,
            summaries,
            sketches,
            self.created_ts,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    pub fn to_compressed(&self) -> std::io::Result<Vec<u8>> {
        let cbor = self.to_cbor();
        zstd::encode_all(&cbor[..], 0).map_err(std::io::Error::other)
    }
}

/// Daily catalog writer
pub struct DailyCatalogWriter {
    catalog_dir: PathBuf,
    catalog: DailyCatalog,
    // Accumulators for sketches
    process_counts: HashMap<String, u64>,
    ip_counts: HashMap<String, u64>,
    file_counts: HashMap<String, u64>,
    user_counts: HashMap<String, u64>,
}

impl DailyCatalogWriter {
    pub fn new(catalog_dir: &Path, date: &str, node_id: &str) -> std::io::Result<Self> {
        let day_dir = catalog_dir
            .join(&date[0..4]) // YYYY
            .join(&date[5..7]) // MM
            .join(&date[8..10]); // DD
        std::fs::create_dir_all(&day_dir)?;

        Ok(Self {
            catalog_dir: day_dir,
            catalog: DailyCatalog::new(date, node_id),
            process_counts: HashMap::new(),
            ip_counts: HashMap::new(),
            file_counts: HashMap::new(),
            user_counts: HashMap::new(),
        })
    }

    /// Add a window summary
    pub fn add_window(&mut self, summary: WindowSummary) {
        self.catalog.add_window(summary);
    }

    /// Record a process execution for top-N tracking
    pub fn record_process(&mut self, process_name: &str) {
        *self
            .process_counts
            .entry(process_name.to_string())
            .or_insert(0) += 1;
        self.catalog.sketches.event_counts.proc_exec += 1;
    }

    /// Record an outbound IP for top-N tracking
    pub fn record_outbound_ip(&mut self, ip: &str) {
        *self.ip_counts.entry(ip.to_string()).or_insert(0) += 1;
        self.catalog.sketches.event_counts.net_connect += 1;
    }

    /// Record a file access for top-N tracking
    pub fn record_file(&mut self, path: &str) {
        *self.file_counts.entry(path.to_string()).or_insert(0) += 1;
    }

    /// Record a user for top-N tracking
    pub fn record_user(&mut self, user: &str) {
        *self.user_counts.entry(user.to_string()).or_insert(0) += 1;
    }

    /// Record an event type
    pub fn record_event_type(&mut self, event_type: &str) {
        self.catalog.sketches.event_counts.increment(event_type);
    }

    /// Set anomaly score
    pub fn set_anomaly_score(&mut self, score: f64) {
        self.catalog.sketches.set_anomaly_score(score);
    }

    /// Record an alert
    pub fn record_alert(&mut self) {
        self.catalog.sketches.increment_alerts();
    }

    /// Finalize and write the catalog
    pub fn finalize(&mut self, top_n: usize) -> std::io::Result<PathBuf> {
        // Build top-N lists
        self.catalog
            .sketches
            .set_top_processes(self.top_n(&self.process_counts, top_n));
        self.catalog
            .sketches
            .set_top_outbound_ips(self.top_n(&self.ip_counts, top_n));
        self.catalog
            .sketches
            .set_top_files(self.top_n(&self.file_counts, top_n));
        self.catalog
            .sketches
            .set_top_users(self.top_n(&self.user_counts, top_n));

        // Write compressed catalog
        let path = self.catalog_dir.join("day.cbor.zst");
        let compressed = self.catalog.to_compressed()?;
        std::fs::write(&path, compressed)?;

        Ok(path)
    }

    fn top_n(&self, counts: &HashMap<String, u64>, n: usize) -> Vec<TopEntry> {
        let mut entries: Vec<_> = counts.iter().collect();
        entries.sort_by(|a, b| b.1.cmp(a.1));
        entries
            .into_iter()
            .take(n)
            .map(|(k, v)| TopEntry::new(k, *v))
            .collect()
    }
}

/// Daily catalog reader
pub struct DailyCatalogReader {
    catalog_dir: PathBuf,
}

impl DailyCatalogReader {
    pub fn new(catalog_dir: &Path) -> Self {
        Self {
            catalog_dir: catalog_dir.to_path_buf(),
        }
    }

    /// Load catalog for a specific date
    pub fn load(&self, date: &str) -> std::io::Result<Option<DailyCatalog>> {
        let path = self
            .catalog_dir
            .join(&date[0..4])
            .join(&date[5..7])
            .join(&date[8..10])
            .join("day.cbor.zst");

        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;
        let decompressed = zstd::decode_all(&data[..]).map_err(std::io::Error::other)?;
        let catalog = parse_catalog(&decompressed)?;
        Ok(Some(catalog))
    }

    /// List available dates
    pub fn list_dates(&self) -> std::io::Result<Vec<String>> {
        let mut dates = Vec::new();
        self.scan_years(&mut dates)?;
        dates.sort();
        Ok(dates)
    }

    fn scan_years(&self, dates: &mut Vec<String>) -> std::io::Result<()> {
        let rd = match std::fs::read_dir(&self.catalog_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for year_entry in rd.flatten() {
            if !year_entry.file_type()?.is_dir() {
                continue;
            }
            let year = year_entry.file_name().to_string_lossy().to_string();
            if year.len() != 4 || year.parse::<u32>().is_err() {
                continue;
            }
            self.scan_months(&year_entry.path(), &year, dates)?;
        }
        Ok(())
    }

    fn scan_months(
        &self,
        year_dir: &Path,
        year: &str,
        dates: &mut Vec<String>,
    ) -> std::io::Result<()> {
        for month_entry in std::fs::read_dir(year_dir)?.flatten() {
            if !month_entry.file_type()?.is_dir() {
                continue;
            }
            let month = month_entry.file_name().to_string_lossy().to_string();
            if month.len() != 2 || month.parse::<u32>().is_err() {
                continue;
            }
            self.scan_days(&month_entry.path(), year, &month, dates)?;
        }
        Ok(())
    }

    fn scan_days(
        &self,
        month_dir: &Path,
        year: &str,
        month: &str,
        dates: &mut Vec<String>,
    ) -> std::io::Result<()> {
        for day_entry in std::fs::read_dir(month_dir)?.flatten() {
            if !day_entry.file_type()?.is_dir() {
                continue;
            }
            let day = day_entry.file_name().to_string_lossy().to_string();
            if day.len() != 2 || day.parse::<u32>().is_err() {
                continue;
            }
            if day_entry.path().join("day.cbor.zst").exists() {
                dates.push(format!("{}-{}-{}", year, month, day));
            }
        }
        Ok(())
    }
}

fn parse_catalog(data: &[u8]) -> std::io::Result<DailyCatalog> {
    let v: ciborium::value::Value = ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid catalog format"));
    };

    if arr.len() < 8 {
        return Err(std::io::Error::other("catalog too short"));
    }

    let date = match arr.get(1) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let node_id = match arr.get(2) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let total_events = match arr.get(3) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let total_windows = match arr.get(4) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let created_ts = match arr.get(7) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    Ok(DailyCatalog {
        date,
        node_id,
        window_summaries: Vec::new(), // Simplified: not parsing full summaries
        sketches: DailySketches::default(),
        total_events,
        total_windows,
        created_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn window_summary_creation() {
        let root: [u8; 32] = Sha256::digest(b"test").into();
        let summary = WindowSummary::new(1000, 2000, "node1", 100, root);
        assert_eq!(summary.event_count, 100);
    }

    #[test]
    fn daily_catalog_accumulation() {
        let mut catalog = DailyCatalog::new("2024-01-01", "node1");
        let root: [u8; 32] = Sha256::digest(b"test").into();

        catalog.add_window(WindowSummary::new(1000, 2000, "node1", 50, root));
        catalog.add_window(WindowSummary::new(2000, 3000, "node1", 75, root));

        assert_eq!(catalog.total_events, 125);
        assert_eq!(catalog.total_windows, 2);
    }

    #[test]
    fn event_type_counts() {
        let mut counts = EventTypeCounts::default();
        counts.increment("proc_exec");
        counts.increment("proc_exec");
        counts.increment("file_open");
        counts.increment("unknown");

        assert_eq!(counts.proc_exec, 2);
        assert_eq!(counts.file_open, 1);
        assert_eq!(counts.other, 1);
        assert_eq!(counts.total(), 4);
    }

    #[test]
    fn catalog_writer_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_catalog_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let mut writer = DailyCatalogWriter::new(&tmp, "2024-01-15", "node1").unwrap();

        // Add some data
        let root: [u8; 32] = Sha256::digest(b"test").into();
        writer.add_window(WindowSummary::new(1000, 2000, "node1", 100, root));

        writer.record_process("/bin/bash");
        writer.record_process("/bin/bash");
        writer.record_process("/usr/bin/python");
        writer.record_outbound_ip("8.8.8.8");
        writer.record_file("/etc/passwd");
        writer.set_anomaly_score(0.75);
        writer.record_alert();

        let path = writer.finalize(10).unwrap();
        assert!(path.exists());

        // Test reader
        let reader = DailyCatalogReader::new(&tmp);
        let catalog = reader.load("2024-01-15").unwrap().unwrap();
        assert_eq!(catalog.total_events, 100);
        assert_eq!(catalog.total_windows, 1);

        let dates = reader.list_dates().unwrap();
        assert!(dates.contains(&"2024-01-15".to_string()));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
