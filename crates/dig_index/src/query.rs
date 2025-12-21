// Advanced query functions for dig_index database

use rusqlite::{params, Connection, Result, Error as RusqliteError};
use crate::DigIndexEntry;

/// Query builder for dig_index
pub struct DigIndexQuery {
    tenant_id: Option<String>,
    time_start: Option<u64>,
    time_end: Option<u64>,
    svc_commit_id: Option<String>,
    infra_version_id: Option<String>,
    camera_frame_id: Option<String>,
    actor_did: Option<String>,
    compliance_framework: Option<String>,
    compliance_burn_id: Option<String>,
    policy_decision: Option<String>,
    limit: Option<usize>,
}

impl DigIndexQuery {
    pub fn new() -> Self {
        Self {
            tenant_id: None,
            time_start: None,
            time_end: None,
            svc_commit_id: None,
            infra_version_id: None,
            camera_frame_id: None,
            actor_did: None,
            compliance_framework: None,
            compliance_burn_id: None,
            policy_decision: None,
            limit: None,
        }
    }

    pub fn tenant(mut self, tenant_id: String) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    pub fn time_range(mut self, start: u64, end: u64) -> Self {
        self.time_start = Some(start);
        self.time_end = Some(end);
        self
    }

    pub fn svc_commit(mut self, svc_commit_id: String) -> Self {
        self.svc_commit_id = Some(svc_commit_id);
        self
    }

    pub fn infra_version(mut self, infra_version_id: String) -> Self {
        self.infra_version_id = Some(infra_version_id);
        self
    }

    pub fn camera_frame(mut self, frame_id: String) -> Self {
        self.camera_frame_id = Some(frame_id);
        self
    }

    pub fn actor(mut self, actor_did: String) -> Self {
        self.actor_did = Some(actor_did);
        self
    }

    pub fn compliance(mut self, framework: String) -> Self {
        self.compliance_framework = Some(framework);
        self
    }

    pub fn burn(mut self, burn_id: String) -> Self {
        self.compliance_burn_id = Some(burn_id);
        self
    }

    pub fn decision(mut self, decision: String) -> Self {
        self.policy_decision = Some(decision);
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Execute query against database
    pub fn execute(&self, db_path: &str) -> Result<Vec<DigIndexEntry>> {
        let conn = Connection::open(db_path)?;
        
        let mut sql = String::from("SELECT DISTINCT d.* FROM digs d");
        let mut joins = Vec::new();
        let mut wheres = Vec::new();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        // Add joins for related tables
        if self.svc_commit_id.is_some() {
            joins.push("JOIN dig_svc_commits svc ON d.file_id = svc.file_id");
        }
        if self.camera_frame_id.is_some() {
            joins.push("JOIN dig_camera_frames cf ON d.file_id = cf.file_id");
        }
        if self.actor_did.is_some() {
            joins.push("JOIN dig_actors a ON d.file_id = a.file_id");
        }

        // Build WHERE clauses
        if let Some(ref tenant) = self.tenant_id {
            wheres.push("d.tenant_id = ?");
            params_vec.push(Box::new(tenant.clone()));
        }
        if let Some(start) = self.time_start {
            wheres.push("d.time_start >= ?");
            params_vec.push(Box::new(start as i64));
        }
        if let Some(end) = self.time_end {
            wheres.push("d.time_end <= ?");
            params_vec.push(Box::new(end as i64));
        }
        if let Some(ref svc) = self.svc_commit_id {
            wheres.push("svc.svc_commit_id = ?");
            params_vec.push(Box::new(svc.clone()));
        }
        if let Some(ref infra) = self.infra_version_id {
            wheres.push("d.infra_version_id = ?");
            params_vec.push(Box::new(infra.clone()));
        }
        if let Some(ref frame) = self.camera_frame_id {
            wheres.push("cf.frame_id = ?");
            params_vec.push(Box::new(frame.clone()));
        }
        if let Some(ref actor) = self.actor_did {
            wheres.push("a.actor_did = ?");
            params_vec.push(Box::new(actor.clone()));
        }
        if let Some(ref framework) = self.compliance_framework {
            wheres.push("d.compliance_framework = ?");
            params_vec.push(Box::new(framework.clone()));
        }
        if let Some(ref burn) = self.compliance_burn_id {
            wheres.push("d.compliance_burn_id = ?");
            params_vec.push(Box::new(burn.clone()));
        }
        if let Some(ref decision) = self.policy_decision {
            wheres.push("d.policy_decision = ?");
            params_vec.push(Box::new(decision.clone()));
        }

        // Assemble query
        if !joins.is_empty() {
            sql.push_str(" ");
            sql.push_str(&joins.join(" "));
        }
        if !wheres.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&wheres.join(" AND "));
        }
        sql.push_str(" ORDER BY d.time_start DESC");
        if let Some(limit) = self.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }

        // Prepare statement; if the digs table does not exist yet (fresh DB),
        // treat this as "no rows" rather than a hard error so callers like
        // evidence-package-export can operate before any dig files are built.
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                if let RusqliteError::SqliteFailure(_, Some(ref msg)) = e {
                    if msg.contains("no such table: digs") {
                        return Ok(Vec::new());
                    }
                }
                return Err(e);
            }
        };
        
        // Convert params_vec to references
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();
        
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok(DigIndexEntry {
                file_id: row.get(0)?,
                root_id: row.get(1)?,
                tenant_id: row.get(2)?,
                time_start: row.get::<_, i64>(3)? as u64,
                time_end: row.get::<_, i64>(4)? as u64,
                record_count: row.get::<_, i64>(5)? as usize,
                merkle_root: row.get(6)?,
                snark_root: None, // Not in main table
                policy_name: row.get(7)?,
                policy_version: row.get(8)?,
                policy_decision: row.get(9)?,
                storage_path: row.get(10)?,
                policy_commit_id: None, // Legacy field
                prev_index_hash: None, // Not in DB
                svc_commits: Vec::new(), // Loaded separately if needed
                infra_version_id: row.get(11)?,
                camera_frames: Vec::new(), // Loaded separately if needed
                actor_dids: Vec::new(), // Loaded separately if needed
                compliance_framework: row.get(12)?,
                compliance_burn_id: row.get(13)?,
                file_hash: row.get(14)?,
                compression: row.get(15)?,
                encryption: row.get(16)?,
                signature: row.get(17)?,
                schema_version: row.get::<_, i64>(18)? as u32,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }
}

impl Default for DigIndexQuery {
    fn default() -> Self {
        Self::new()
    }
}

/// Get all DigFiles for a specific SVC commit
pub fn files_by_svc_commit(db_path: &str, svc_commit_id: &str) -> Result<Vec<DigIndexEntry>> {
    DigIndexQuery::new()
        .svc_commit(svc_commit_id.to_string())
        .execute(db_path)
}

/// Get all DigFiles for a specific CCTV frame
pub fn files_by_camera_frame(db_path: &str, frame_id: &str) -> Result<Vec<DigIndexEntry>> {
    DigIndexQuery::new()
        .camera_frame(frame_id.to_string())
        .execute(db_path)
}

/// Get all DigFiles for a specific actor
pub fn files_by_actor(db_path: &str, actor_did: &str) -> Result<Vec<DigIndexEntry>> {
    DigIndexQuery::new()
        .actor(actor_did.to_string())
        .execute(db_path)
}

/// Get all DigFiles for a compliance burn
pub fn files_by_compliance_burn(db_path: &str, burn_id: &str) -> Result<Vec<DigIndexEntry>> {
    DigIndexQuery::new()
        .burn(burn_id.to_string())
        .execute(db_path)
}

/// Get statistics for a tenant
pub fn tenant_statistics(db_path: &str, tenant_id: &str) -> Result<TenantStats> {
    let conn = Connection::open(db_path)?;
    
    let mut stmt = conn.prepare(
        "SELECT 
            COUNT(*) as file_count,
            SUM(record_count) as total_records,
            MIN(time_start) as earliest,
            MAX(time_end) as latest
        FROM digs WHERE tenant_id = ?"
    )?;
    
    let stats = stmt.query_row(params![tenant_id], |row| {
        Ok(TenantStats {
            file_count: row.get::<_, i64>(0)? as usize,
            total_records: row.get::<_, i64>(1)? as usize,
            earliest_timestamp: row.get::<_, i64>(2)? as u64,
            latest_timestamp: row.get::<_, i64>(3)? as u64,
        })
    })?;
    
    Ok(stats)
}

#[derive(Debug, Clone)]
pub struct TenantStats {
    pub file_count: usize,
    pub total_records: usize,
    pub earliest_timestamp: u64,
    pub latest_timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_builder_constructs() {
        let query = DigIndexQuery::new()
            .tenant("tenant_a".to_string())
            .time_range(100, 200)
            .svc_commit("svc_123".to_string())
            .limit(10);

        assert_eq!(query.tenant_id, Some("tenant_a".to_string()));
        assert_eq!(query.time_start, Some(100));
        assert_eq!(query.limit, Some(10));
    }
}
