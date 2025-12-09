use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use rusqlite::{params, Connection};
use core_types::hash_bytes;

/// Minimal index entry for a sealed DigFile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigIndexEntry {
    pub file_id: String,
    pub root_id: String,
    pub tenant_id: Option<String>,
    pub time_start: u64,
    pub time_end: u64,
    pub record_count: usize,
    pub merkle_root: String,
    #[serde(default)]
    pub snark_root: Option<String>,
    pub policy_name: Option<String>,
    pub policy_version: Option<String>,
    pub policy_decision: Option<String>,
    pub storage_path: Option<String>,
    #[serde(default)]
    pub prev_index_hash: Option<String>,
}

fn compute_index_hash(prev: Option<&str>, line: &[u8]) -> String {
    let mut data = Vec::new();
    if let Some(p) = prev {
        data.extend_from_slice(p.as_bytes());
    }
    data.extend_from_slice(line);

    let hash = hash_bytes(&data);
    let mut s = String::with_capacity(64);
    for b in &hash.0 {
        s.push_str(&format!("{:02x}", b));
    }

    s
}

/// Append a JSON line describing a DigFile to the local dig index file.
///
/// The target file is controlled by UTLD_DIG_INDEX, defaulting to
/// `./dig_index.jsonl` when unset.
pub fn append_index_entry(entry: &DigIndexEntry) -> std::io::Result<()> {
    let path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());

    let head_path = format!("{}.head", path);
    let prev_hash = std::fs::read_to_string(&head_path)
        .ok()
        .map(|s| s.trim().to_string());

    let mut chained_entry = entry.clone();
    chained_entry.prev_index_hash = prev_hash.clone();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    use fs2::FileExt;

    // Serialize appends with an advisory file lock so multiple writers cannot
    // interleave dig index entries.
    file.lock_exclusive()?;

    let line = serde_json::to_string(&chained_entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;

    let current_hash = compute_index_hash(prev_hash.as_deref(), line.as_bytes());
    if let Err(e) = std::fs::write(&head_path, format!("{}\n", current_hash)) {
        eprintln!("failed to update dig index head {}: {}", head_path, e);
    }

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
