use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use rusqlite::{params, Connection};

/// Minimal index entry for a sealed DigFile.
#[derive(Debug, Serialize, Deserialize)]
pub struct DigIndexEntry {
    pub file_id: String,
    pub root_id: String,
    pub tenant_id: Option<String>,
    pub time_start: u64,
    pub time_end: u64,
    pub record_count: usize,
    pub merkle_root: String,
    pub policy_name: Option<String>,
    pub policy_version: Option<String>,
    pub policy_decision: Option<String>,
    pub storage_path: Option<String>,
}

/// Append a JSON line describing a DigFile to the local dig index file.
///
/// The target file is controlled by UTLD_DIG_INDEX, defaulting to
/// `./dig_index.jsonl` when unset.
pub fn append_index_entry(entry: &DigIndexEntry) -> std::io::Result<()> {
    let path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    let line = serde_json::to_string(entry).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;

    // Optionally mirror entries into a local SQLite DB if UTLD_DIG_INDEX_DB is set.
    if let Ok(db_path) = std::env::var("UTLD_DIG_INDEX_DB") {
        if let Err(e) = append_index_entry_db(&db_path, entry) {
            eprintln!("failed to append dig index entry to db {}: {}", db_path, e);
        }
    }

    Ok(())
}

fn append_index_entry_db(path: &str, entry: &DigIndexEntry) -> Result<(), rusqlite::Error> {
    let conn = Connection::open(path)?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS digs (
            file_id TEXT PRIMARY KEY,
            root_id TEXT NOT NULL,
            tenant_id TEXT,
            time_start INTEGER NOT NULL,
            time_end INTEGER NOT NULL,
            record_count INTEGER NOT NULL,
            merkle_root TEXT NOT NULL,
            policy_name TEXT,
            policy_version TEXT,
            policy_decision TEXT,
            storage_path TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_digs_tenant_time ON digs(tenant_id, time_start, time_end);
        CREATE INDEX IF NOT EXISTS idx_digs_root_time ON digs(root_id, time_start, time_end);
        CREATE INDEX IF NOT EXISTS idx_digs_policy_decision ON digs(policy_decision);
        ",
    )?;

    conn.execute(
        "INSERT OR REPLACE INTO digs (
            file_id,
            root_id,
            tenant_id,
            time_start,
            time_end,
            record_count,
            merkle_root,
            policy_name,
            policy_version,
            policy_decision,
            storage_path
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            entry.file_id,
            entry.root_id,
            entry.tenant_id.as_deref(),
            entry.time_start as i64,
            entry.time_end as i64,
            entry.record_count as i64,
            entry.merkle_root,
            entry.policy_name.as_deref(),
            entry.policy_version.as_deref(),
            entry.policy_decision.as_deref(),
            entry.storage_path.as_deref(),
        ],
    )?;

    Ok(())
}
