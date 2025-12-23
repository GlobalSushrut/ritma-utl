use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use core_types::hash_bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCommit {
    pub commit_id: String,
    pub parent: Option<String>,
    pub author: String,
    pub timestamp: u64,
    pub message: String,
    pub policy_tree_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTag {
    pub tag: String,
    pub commit_id: String,
    pub framework: Option<String>,
    pub created_by: String,
    pub created_at: u64,
    pub notes: Option<String>,
}

fn commits_path_from_env() -> String {
    std::env::var("UTLD_POLICY_COMMITS").unwrap_or_else(|_| "./policy_commits.jsonl".to_string())
}

fn tags_path_from_env() -> String {
    std::env::var("UTLD_POLICY_TAGS").unwrap_or_else(|_| "./policy_tags.jsonl".to_string())
}

pub fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn read_commits() -> Result<Vec<PolicyCommit>, String> {
    let path = commits_path_from_env();
    let file = match OpenOptions::new().read(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(Vec::new());
            }
            return Err(format!("failed to open policy commits {path}: {e}"));
        }
    };

    let reader = BufReader::new(file);
    let mut commits = Vec::new();
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("failed to read policy commit line: {e}");
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<PolicyCommit>(&line) {
            Ok(c) => commits.push(c),
            Err(e) => eprintln!("failed to parse policy commit JSON: {e}"),
        }
    }

    Ok(commits)
}

pub fn read_tags() -> Result<Vec<PolicyTag>, String> {
    let path = tags_path_from_env();
    let file = match OpenOptions::new().read(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(Vec::new());
            }
            return Err(format!("failed to open policy tags {path}: {e}"));
        }
    };

    let reader = BufReader::new(file);
    let mut tags = Vec::new();
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("failed to read policy tag line: {e}");
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<PolicyTag>(&line) {
            Ok(t) => tags.push(t),
            Err(e) => eprintln!("failed to parse policy tag JSON: {e}"),
        }
    }

    Ok(tags)
}

pub fn append_commit(commit: &PolicyCommit) -> Result<(), String> {
    let path = commits_path_from_env();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("failed to open policy commits {path}: {e}"))?;

    let line = serde_json::to_string(commit)
        .map_err(|e| format!("failed to serialize policy commit: {e}"))?;
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|e| format!("failed to write policy commit: {e}"))?;
    file.flush()
        .map_err(|e| format!("failed to flush policy commits {path}: {e}"))?;
    Ok(())
}

pub fn append_tag(tag: &PolicyTag) -> Result<(), String> {
    let path = tags_path_from_env();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("failed to open policy tags {path}: {e}"))?;

    let line =
        serde_json::to_string(tag).map_err(|e| format!("failed to serialize policy tag: {e}"))?;
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|e| format!("failed to write policy tag: {e}"))?;
    file.flush()
        .map_err(|e| format!("failed to flush policy tags {path}: {e}"))?;
    Ok(())
}

pub fn compute_policy_tree_hash(policy_bytes: &[u8]) -> String {
    let h = hash_bytes(policy_bytes);
    let mut s = String::with_capacity(64);
    for b in &h.0 {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn compute_commit_id(
    parent: Option<&str>,
    author: &str,
    message: &str,
    policy_tree_hash: &str,
    timestamp: u64,
) -> String {
    let mut data = Vec::new();
    if let Some(p) = parent {
        data.extend_from_slice(p.as_bytes());
    }
    data.extend_from_slice(author.as_bytes());
    data.extend_from_slice(message.as_bytes());
    data.extend_from_slice(policy_tree_hash.as_bytes());
    data.extend_from_slice(&timestamp.to_le_bytes());

    let h = hash_bytes(&data);
    let mut s = String::with_capacity(64);
    for b in &h.0 {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
