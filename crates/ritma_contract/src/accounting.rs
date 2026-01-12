//! Extended accounting with top talkers (2.10)
//!
//! This module extends the accounting ledger with per-process/service
//! breakdown for identifying top talkers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Top talker entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopTalker {
    pub identifier: String,
    pub talker_type: TalkerType,
    pub event_count: u64,
    pub bytes_generated: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TalkerType {
    Process = 0,
    Service = 1,
    Container = 2,
    User = 3,
    Host = 4,
}

impl TalkerType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Service => "service",
            Self::Container => "container",
            Self::User => "user",
            Self::Host => "host",
        }
    }
}

/// Extended accounting entry with top talkers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedAccounting {
    pub day_ts: i64,
    pub node_id: String,
    pub total_events: u64,
    pub bytes_raw: u64,
    pub bytes_compressed: u64,
    pub bytes_deduped: u64,
    pub top_processes: Vec<TopTalker>,
    pub top_services: Vec<TopTalker>,
    pub top_containers: Vec<TopTalker>,
    pub top_users: Vec<TopTalker>,
    pub category_breakdown: CategoryBreakdown,
}

/// Bytes breakdown by category
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryBreakdown {
    pub inst_blocks: u64,
    pub indexes: u64,
    pub cas_chunks: u64,
    pub proofs: u64,
    pub catalog: u64,
    pub graph: u64,
    pub other: u64,
}

impl CategoryBreakdown {
    pub fn total(&self) -> u64 {
        self.inst_blocks
            + self.indexes
            + self.cas_chunks
            + self.proofs
            + self.catalog
            + self.graph
            + self.other
    }
}

impl ExtendedAccounting {
    pub fn new(day_ts: i64, node_id: &str) -> Self {
        Self {
            day_ts,
            node_id: node_id.to_string(),
            total_events: 0,
            bytes_raw: 0,
            bytes_compressed: 0,
            bytes_deduped: 0,
            top_processes: Vec::new(),
            top_services: Vec::new(),
            top_containers: Vec::new(),
            top_users: Vec::new(),
            category_breakdown: CategoryBreakdown::default(),
        }
    }

    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_raw == 0 {
            return 1.0;
        }
        self.bytes_compressed as f64 / self.bytes_raw as f64
    }

    pub fn dedupe_ratio(&self) -> f64 {
        if self.bytes_raw == 0 {
            return 1.0;
        }
        self.bytes_deduped as f64 / self.bytes_raw as f64
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let top_processes: Vec<(&str, &str, u64, u64)> = self
            .top_processes
            .iter()
            .map(|t| (t.identifier.as_str(), t.talker_type.name(), t.event_count, t.bytes_generated))
            .collect();

        let top_services: Vec<(&str, &str, u64, u64)> = self
            .top_services
            .iter()
            .map(|t| (t.identifier.as_str(), t.talker_type.name(), t.event_count, t.bytes_generated))
            .collect();

        let top_containers: Vec<(&str, &str, u64, u64)> = self
            .top_containers
            .iter()
            .map(|t| (t.identifier.as_str(), t.talker_type.name(), t.event_count, t.bytes_generated))
            .collect();

        let top_users: Vec<(&str, &str, u64, u64)> = self
            .top_users
            .iter()
            .map(|t| (t.identifier.as_str(), t.talker_type.name(), t.event_count, t.bytes_generated))
            .collect();

        let category = (
            self.category_breakdown.inst_blocks,
            self.category_breakdown.indexes,
            self.category_breakdown.cas_chunks,
            self.category_breakdown.proofs,
            self.category_breakdown.catalog,
            self.category_breakdown.graph,
            self.category_breakdown.other,
        );

        let tuple = (
            "ritma-ext-accounting@0.1",
            self.day_ts,
            &self.node_id,
            self.total_events,
            self.bytes_raw,
            self.bytes_compressed,
            self.bytes_deduped,
            top_processes,
            top_services,
            top_containers,
            top_users,
            category,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Accounting accumulator for building daily reports
pub struct AccountingAccumulator {
    day_ts: i64,
    node_id: String,
    total_events: u64,
    bytes_raw: u64,
    bytes_compressed: u64,
    bytes_deduped: u64,
    process_stats: HashMap<String, (u64, u64)>, // (events, bytes)
    service_stats: HashMap<String, (u64, u64)>,
    container_stats: HashMap<String, (u64, u64)>,
    user_stats: HashMap<String, (u64, u64)>,
    category_breakdown: CategoryBreakdown,
}

impl AccountingAccumulator {
    pub fn new(day_ts: i64, node_id: &str) -> Self {
        Self {
            day_ts,
            node_id: node_id.to_string(),
            total_events: 0,
            bytes_raw: 0,
            bytes_compressed: 0,
            bytes_deduped: 0,
            process_stats: HashMap::new(),
            service_stats: HashMap::new(),
            container_stats: HashMap::new(),
            user_stats: HashMap::new(),
            category_breakdown: CategoryBreakdown::default(),
        }
    }

    /// Record an event from a process
    pub fn record_process_event(&mut self, process: &str, bytes: u64) {
        self.total_events += 1;
        self.bytes_raw += bytes;
        let entry = self.process_stats.entry(process.to_string()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;
    }

    /// Record an event from a service
    pub fn record_service_event(&mut self, service: &str, bytes: u64) {
        let entry = self.service_stats.entry(service.to_string()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;
    }

    /// Record an event from a container
    pub fn record_container_event(&mut self, container: &str, bytes: u64) {
        let entry = self.container_stats.entry(container.to_string()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;
    }

    /// Record an event from a user
    pub fn record_user_event(&mut self, user: &str, bytes: u64) {
        let entry = self.user_stats.entry(user.to_string()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;
    }

    /// Record compressed bytes
    pub fn record_compressed(&mut self, bytes: u64) {
        self.bytes_compressed += bytes;
    }

    /// Record deduped bytes
    pub fn record_deduped(&mut self, bytes: u64) {
        self.bytes_deduped += bytes;
    }

    /// Record category bytes
    pub fn record_category(&mut self, category: &str, bytes: u64) {
        match category {
            "inst_blocks" => self.category_breakdown.inst_blocks += bytes,
            "indexes" => self.category_breakdown.indexes += bytes,
            "cas_chunks" => self.category_breakdown.cas_chunks += bytes,
            "proofs" => self.category_breakdown.proofs += bytes,
            "catalog" => self.category_breakdown.catalog += bytes,
            "graph" => self.category_breakdown.graph += bytes,
            _ => self.category_breakdown.other += bytes,
        }
    }

    /// Finalize and build the extended accounting report
    pub fn finalize(self, top_n: usize) -> ExtendedAccounting {
        let top_processes = self.top_n_talkers(&self.process_stats, TalkerType::Process, top_n);
        let top_services = self.top_n_talkers(&self.service_stats, TalkerType::Service, top_n);
        let top_containers = self.top_n_talkers(&self.container_stats, TalkerType::Container, top_n);
        let top_users = self.top_n_talkers(&self.user_stats, TalkerType::User, top_n);

        ExtendedAccounting {
            day_ts: self.day_ts,
            node_id: self.node_id,
            total_events: self.total_events,
            bytes_raw: self.bytes_raw,
            bytes_compressed: self.bytes_compressed,
            bytes_deduped: self.bytes_deduped,
            top_processes,
            top_services,
            top_containers,
            top_users,
            category_breakdown: self.category_breakdown,
        }
    }

    fn top_n_talkers(
        &self,
        stats: &HashMap<String, (u64, u64)>,
        talker_type: TalkerType,
        n: usize,
    ) -> Vec<TopTalker> {
        let mut entries: Vec<_> = stats.iter().collect();
        entries.sort_by(|a, b| b.1 .1.cmp(&a.1 .1)); // Sort by bytes descending

        entries
            .into_iter()
            .take(n)
            .map(|(id, (events, bytes))| TopTalker {
                identifier: id.clone(),
                talker_type,
                event_count: *events,
                bytes_generated: *bytes,
            })
            .collect()
    }
}

/// Extended accounting writer
pub struct ExtendedAccountingWriter {
    accounting_dir: PathBuf,
}

impl ExtendedAccountingWriter {
    pub fn new(out_dir: &Path) -> std::io::Result<Self> {
        let accounting_dir = out_dir.join("accounting");
        std::fs::create_dir_all(&accounting_dir)?;
        Ok(Self { accounting_dir })
    }

    /// Write extended accounting for a day
    pub fn write(&self, accounting: &ExtendedAccounting) -> std::io::Result<PathBuf> {
        let dt = chrono::DateTime::from_timestamp(accounting.day_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());

        let day_dir = self
            .accounting_dir
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()));
        std::fs::create_dir_all(&day_dir)?;

        let path = day_dir.join("extended_account.cbor.zst");
        let cbor = accounting.to_cbor();
        let compressed = zstd::encode_all(&cbor[..], 0).map_err(std::io::Error::other)?;
        std::fs::write(&path, compressed)?;

        Ok(path)
    }

    /// Read extended accounting for a day
    pub fn read(&self, day_ts: i64) -> std::io::Result<Option<ExtendedAccounting>> {
        let dt = chrono::DateTime::from_timestamp(day_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());

        let path = self
            .accounting_dir
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()))
            .join("extended_account.cbor.zst");

        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;
        let decompressed = zstd::decode_all(&data[..]).map_err(std::io::Error::other)?;
        let accounting = parse_extended_accounting(&decompressed)?;
        Ok(Some(accounting))
    }
}

use chrono::Datelike;

fn parse_extended_accounting(data: &[u8]) -> std::io::Result<ExtendedAccounting> {
    let v: ciborium::value::Value =
        ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid extended accounting format"));
    };

    if arr.len() < 12 {
        return Err(std::io::Error::other("extended accounting too short"));
    }

    let day_ts = match arr.get(1) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let node_id = match arr.get(2) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let total_events = match arr.get(3) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let bytes_raw = match arr.get(4) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let bytes_compressed = match arr.get(5) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let bytes_deduped = match arr.get(6) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    Ok(ExtendedAccounting {
        day_ts,
        node_id,
        total_events,
        bytes_raw,
        bytes_compressed,
        bytes_deduped,
        top_processes: Vec::new(),
        top_services: Vec::new(),
        top_containers: Vec::new(),
        top_users: Vec::new(),
        category_breakdown: CategoryBreakdown::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounting_accumulator_top_n() {
        let mut acc = AccountingAccumulator::new(1704067200, "node1");

        // Record events from various processes
        for _ in 0..100 {
            acc.record_process_event("/bin/bash", 50);
        }
        for _ in 0..50 {
            acc.record_process_event("/usr/bin/python", 100);
        }
        for _ in 0..25 {
            acc.record_process_event("/usr/bin/curl", 200);
        }

        let report = acc.finalize(2);

        assert_eq!(report.total_events, 175);
        assert_eq!(report.top_processes.len(), 2);
        // bash has most bytes: 100 * 50 = 5000
        // python: 50 * 100 = 5000
        // curl: 25 * 200 = 5000
        // All tied at 5000 bytes, order depends on HashMap iteration
        // Just verify we got 2 entries with correct byte counts
        let total_bytes: u64 = report.top_processes.iter().map(|t| t.bytes_generated).sum();
        assert_eq!(total_bytes, 10000); // Two of the three 5000-byte entries
    }

    #[test]
    fn category_breakdown() {
        let mut acc = AccountingAccumulator::new(1704067200, "node1");

        acc.record_category("inst_blocks", 1000);
        acc.record_category("indexes", 500);
        acc.record_category("proofs", 200);
        acc.record_category("unknown", 100);

        let report = acc.finalize(10);

        assert_eq!(report.category_breakdown.inst_blocks, 1000);
        assert_eq!(report.category_breakdown.indexes, 500);
        assert_eq!(report.category_breakdown.proofs, 200);
        assert_eq!(report.category_breakdown.other, 100);
        assert_eq!(report.category_breakdown.total(), 1800);
    }

    #[test]
    fn extended_accounting_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_ext_acc_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let writer = ExtendedAccountingWriter::new(&tmp).unwrap();

        let mut acc = AccountingAccumulator::new(1704067200, "node1");
        acc.record_process_event("/bin/bash", 100);
        acc.record_compressed(80);
        acc.record_deduped(60);

        let report = acc.finalize(10);
        writer.write(&report).unwrap();

        let loaded = writer.read(1704067200).unwrap().unwrap();
        assert_eq!(loaded.total_events, 1);
        assert_eq!(loaded.bytes_raw, 100);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
