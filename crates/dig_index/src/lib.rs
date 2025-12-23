pub mod query;

use core_types::hash_bytes;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;

pub use query::{
    files_by_actor, files_by_camera_frame, files_by_compliance_burn, files_by_svc_commit,
    tenant_statistics, DigIndexQuery, TenantStats,
};

/// Enhanced index entry for a sealed DigFile with SVC and CCTV correlation.
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
    pub policy_commit_id: Option<String>,
    #[serde(default)]
    pub prev_index_hash: Option<String>,

    // Enhanced SVC metadata
    #[serde(default)]
    pub svc_commits: Vec<String>,
    #[serde(default)]
    pub infra_version_id: Option<String>,

    // CCTV correlation
    #[serde(default)]
    pub camera_frames: Vec<String>,

    // Actor tracking
    #[serde(default)]
    pub actor_dids: Vec<String>,

    // Compliance metadata
    #[serde(default)]
    pub compliance_framework: Option<String>,
    #[serde(default)]
    pub compliance_burn_id: Option<String>,

    // File metadata
    #[serde(default)]
    pub file_hash: Option<String>,
    #[serde(default)]
    pub compression: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,

    // Schema version
    #[serde(default)]
    pub schema_version: u32,
}

impl Default for DigIndexEntry {
    fn default() -> Self {
        Self {
            file_id: String::new(),
            root_id: String::new(),
            tenant_id: None,
            time_start: 0,
            time_end: 0,
            record_count: 0,
            merkle_root: String::new(),
            snark_root: None,
            policy_name: None,
            policy_version: None,
            policy_decision: None,
            storage_path: None,
            policy_commit_id: None,
            prev_index_hash: None,
            svc_commits: Vec::new(),
            infra_version_id: None,
            camera_frames: Vec::new(),
            actor_dids: Vec::new(),
            compliance_framework: None,
            compliance_burn_id: None,
            file_hash: None,
            compression: None,
            encryption: None,
            signature: None,
            schema_version: 2,
        }
    }
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
        s.push_str(&format!("{b:02x}"));
    }

    s
}

fn append_index_entry_to_path(path: &str, entry: &DigIndexEntry) -> std::io::Result<()> {
    let head_path = format!("{path}.head");
    let prev_hash = std::fs::read_to_string(&head_path)
        .ok()
        .map(|s| s.trim().to_string());

    let mut chained_entry = entry.clone();
    chained_entry.prev_index_hash = prev_hash.clone();

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    use fs2::FileExt;

    file.lock_exclusive()?;

    let line = serde_json::to_string(&chained_entry).map_err(std::io::Error::other)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;

    let current_hash = compute_index_hash(prev_hash.as_deref(), line.as_bytes());
    if let Err(e) = std::fs::write(&head_path, format!("{current_hash}\n")) {
        eprintln!("failed to update dig index head {head_path}: {e}");
    }

    Ok(())
}

pub fn append_index_entry(entry: &DigIndexEntry) -> std::io::Result<()> {
    let path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());

    append_index_entry_to_path(&path, entry)?;

    if let Ok(cold_path) = std::env::var("UTLD_DIG_INDEX_COLD") {
        if !cold_path.trim().is_empty() {
            if let Err(e) = append_index_entry_to_path(&cold_path, entry) {
                eprintln!("failed to append dig index entry to cold path {cold_path}: {e}");
            }
        }
    }

    if let Ok(db_path) = std::env::var("UTLD_DIG_INDEX_DB") {
        if let Err(e) = append_index_entry_db(&db_path, entry) {
            eprintln!("failed to append dig index entry to db {db_path}: {e}");
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
            storage_path TEXT,
            infra_version_id TEXT,
            compliance_framework TEXT,
            compliance_burn_id TEXT,
            file_hash TEXT,
            compression TEXT,
            encryption TEXT,
            signature TEXT,
            schema_version INTEGER DEFAULT 2
        );
        CREATE INDEX IF NOT EXISTS idx_digs_tenant_time ON digs(tenant_id, time_start, time_end);
        CREATE INDEX IF NOT EXISTS idx_digs_root_time ON digs(root_id, time_start, time_end);
        CREATE INDEX IF NOT EXISTS idx_digs_policy_decision ON digs(policy_decision);
        CREATE INDEX IF NOT EXISTS idx_digs_infra_version ON digs(infra_version_id);
        CREATE INDEX IF NOT EXISTS idx_digs_compliance ON digs(compliance_framework, compliance_burn_id);
        CREATE INDEX IF NOT EXISTS idx_digs_file_hash ON digs(file_hash);
        
        CREATE TABLE IF NOT EXISTS dig_svc_commits (
            file_id TEXT NOT NULL,
            svc_commit_id TEXT NOT NULL,
            PRIMARY KEY (file_id, svc_commit_id),
            FOREIGN KEY (file_id) REFERENCES digs(file_id)
        );
        CREATE INDEX IF NOT EXISTS idx_svc_commits ON dig_svc_commits(svc_commit_id);
        
        CREATE TABLE IF NOT EXISTS dig_camera_frames (
            file_id TEXT NOT NULL,
            frame_id TEXT NOT NULL,
            PRIMARY KEY (file_id, frame_id),
            FOREIGN KEY (file_id) REFERENCES digs(file_id)
        );
        CREATE INDEX IF NOT EXISTS idx_camera_frames ON dig_camera_frames(frame_id);
        
        CREATE TABLE IF NOT EXISTS dig_actors (
            file_id TEXT NOT NULL,
            actor_did TEXT NOT NULL,
            PRIMARY KEY (file_id, actor_did),
            FOREIGN KEY (file_id) REFERENCES digs(file_id)
        );
        CREATE INDEX IF NOT EXISTS idx_actors ON dig_actors(actor_did);
        ",
    )?;

    conn.execute(
        "INSERT OR REPLACE INTO digs (
            file_id, root_id, tenant_id, time_start, time_end, record_count,
            merkle_root, policy_name, policy_version, policy_decision, storage_path,
            infra_version_id, compliance_framework, compliance_burn_id,
            file_hash, compression, encryption, signature, schema_version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
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
            entry.infra_version_id.as_deref(),
            entry.compliance_framework.as_deref(),
            entry.compliance_burn_id.as_deref(),
            entry.file_hash.as_deref(),
            entry.compression.as_deref(),
            entry.encryption.as_deref(),
            entry.signature.as_deref(),
            entry.schema_version as i64,
        ],
    )?;

    // Insert SVC commits
    for svc in &entry.svc_commits {
        conn.execute(
            "INSERT OR IGNORE INTO dig_svc_commits (file_id, svc_commit_id) VALUES (?1, ?2)",
            params![entry.file_id, svc],
        )?;
    }

    // Insert camera frames
    for frame in &entry.camera_frames {
        conn.execute(
            "INSERT OR IGNORE INTO dig_camera_frames (file_id, frame_id) VALUES (?1, ?2)",
            params![entry.file_id, frame],
        )?;
    }

    // Insert actors
    for actor in &entry.actor_dids {
        conn.execute(
            "INSERT OR IGNORE INTO dig_actors (file_id, actor_did) VALUES (?1, ?2)",
            params![entry.file_id, actor],
        )?;
    }

    Ok(())
}
