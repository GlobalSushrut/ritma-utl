use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};

use clock::TimeTick;
use compliance_index::ControlEvalRecord;
use dig_index::DigIndexEntry;
use security_events::DecisionEvent;

use crate::containers::ParamBundle;
use crate::observability;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPostureRow {
    pub framework: String,
    pub control_id: String,
    pub policy_commit_id: Option<String>,
    pub tenant_id: Option<String>,
    pub passed: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRow {
    pub ts: u64,
    pub tenant_id: String,
    pub root_id: String,
    pub entity_id: String,
    pub event_kind: String,
    pub policy_decision: String,
    pub snark_status: String,
    pub policy_commit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigCoverageRow {
    pub tenant_id: String,
    pub root_id: String,
    pub file_count: u64,
    pub latest_time_end: u64,
}

/// High-level, human-readable infra security report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub title: String,
    pub generated_at: u64,
    pub tenant_id: Option<String>,
    pub summary: String,
    pub control_posture: Vec<ControlPostureRow>,
    pub incidents: Vec<IncidentRow>,
    pub dig_coverage: Vec<DigCoverageRow>,
    pub findings: Vec<String>,
}

impl SecurityReport {
    /// Generate a full infra report by reading standard JSONL logs.
    ///
    /// - Compliance index: UTLD_COMPLIANCE_INDEX (ControlEvalRecord JSONL)
    /// - Decision events: UTLD_DECISION_EVENTS (DecisionEvent JSONL)
    /// - Dig index      : UTLD_DIG_INDEX (DigIndexEntry JSONL)
    pub fn generate_for_tenant(tenant_filter: Option<&str>) -> std::io::Result<Self> {
        let start = std::time::Instant::now();
        let tenant_owned = tenant_filter.map(|s| s.to_string());

        let res: std::io::Result<Self> = (|| {
            let now = TimeTick::now().raw_time;

            let control_posture = aggregate_controls(tenant_filter)?;
            let incidents = aggregate_incidents(tenant_filter, 200)?;
            let dig_coverage = aggregate_dig_coverage(tenant_filter)?;

            let mut findings = Vec::new();
            findings.push(format!("controls_rows: {}", control_posture.len()));
            findings.push(format!("incidents_rows: {}", incidents.len()));
            findings.push(format!("dig_roots: {}", dig_coverage.len()));

            Ok(Self {
                title: "SecurityKit infra report".to_string(),
                generated_at: now,
                tenant_id: tenant_filter.map(|s| s.to_string()),
                summary: "Consolidated compliance, incident, and evidence coverage report"
                    .to_string(),
                control_posture,
                incidents,
                dig_coverage,
                findings,
            })
        })();

        let latency = Some(start.elapsed().as_millis() as u64);
        match &res {
            Ok(_) => observability::emit_slo_event(
                "reporting",
                "generate_for_tenant",
                tenant_owned.as_deref(),
                None,
                "ok",
                latency,
                None,
            ),
            Err(e) => observability::emit_slo_event(
                "reporting",
                "generate_for_tenant",
                tenant_owned.as_deref(),
                None,
                "error",
                latency,
                Some(&e.to_string()),
            ),
        }

        res
    }

    /// Lightweight report from in-memory params (for SDK users).
    pub fn from_params(title: impl Into<String>, bundle: &ParamBundle) -> Self {
        let title = title.into();
        let mut findings = Vec::new();
        findings.push(format!("general_keys: {}", bundle.general.0.len()));
        findings.push(format!("secret_keys: {}", bundle.secrets.0.len()));
        if let Some(snap) = &bundle.snapshot {
            findings.push(format!("snapshot: {} at {}", snap.label, snap.ts));
        }
        let now = TimeTick::now().raw_time;
        Self {
            title,
            generated_at: now,
            tenant_id: None,
            summary: "SecurityKit param bundle report".to_string(),
            control_posture: Vec::new(),
            incidents: Vec::new(),
            dig_coverage: Vec::new(),
            findings,
        }
    }
}

fn aggregate_controls(tenant_filter: Option<&str>) -> std::io::Result<Vec<ControlPostureRow>> {
    use std::fs::File;

    let idx_path = std::env::var("UTLD_COMPLIANCE_INDEX")
        .unwrap_or_else(|_| "./compliance_index.jsonl".to_string());

    let file = match File::open(&idx_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);

    type StatsKey = (String, String, Option<String>, Option<String>);
    type StatsValue = (u64, u64);
    let mut stats: BTreeMap<StatsKey, StatsValue> = BTreeMap::new();

    for line_res in reader.lines() {
        let line = line_res?;
        if line.trim().is_empty() {
            continue;
        }

        let rec: ControlEvalRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(tid) = tenant_filter {
            if rec.tenant_id.as_deref() != Some(tid) {
                continue;
            }
        }

        let key = (
            rec.framework.clone(),
            rec.control_id.clone(),
            rec.commit_id.clone(),
            rec.tenant_id.clone(),
        );
        let entry = stats.entry(key).or_insert((0, 0));
        entry.1 += 1;
        if rec.passed {
            entry.0 += 1;
        }
    }

    let mut rows = Vec::new();
    for ((fw, cid, commit, tenant), (passed, total)) in stats {
        rows.push(ControlPostureRow {
            framework: fw,
            control_id: cid,
            policy_commit_id: commit,
            tenant_id: tenant,
            passed,
            total,
        });
    }

    Ok(rows)
}

fn aggregate_incidents(
    tenant_filter: Option<&str>,
    limit: usize,
) -> std::io::Result<Vec<IncidentRow>> {
    use std::fs::File;

    let path = std::env::var("UTLD_DECISION_EVENTS")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());

    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);

    let mut incidents: Vec<DecisionEvent> = Vec::new();

    for line_res in reader.lines() {
        let line = line_res?;
        if line.trim().is_empty() {
            continue;
        }

        let ev: DecisionEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if let Some(tid) = tenant_filter {
            if ev.tenant_id.as_deref() != Some(tid) {
                continue;
            }
        }

        let is_deny = ev.policy_decision == "deny";
        let is_high_threat = matches!(
            ev.snark_high_threat_merkle_status.as_deref(),
            Some("invalid") | Some("error") | Some("high")
        );

        if is_deny || is_high_threat {
            incidents.push(ev);
        }
    }

    incidents.sort_by_key(|e| e.ts);
    incidents.reverse();

    let mut rows = Vec::new();
    for ev in incidents.into_iter().take(limit) {
        rows.push(IncidentRow {
            ts: ev.ts,
            tenant_id: ev.tenant_id.unwrap_or_default(),
            root_id: ev.root_id,
            entity_id: ev.entity_id,
            event_kind: ev.event_kind,
            policy_decision: ev.policy_decision,
            snark_status: ev.snark_high_threat_merkle_status.unwrap_or_default(),
            policy_commit_id: ev.policy_commit_id.unwrap_or_default(),
        });
    }

    Ok(rows)
}

fn aggregate_dig_coverage(tenant_filter: Option<&str>) -> std::io::Result<Vec<DigCoverageRow>> {
    use std::fs::File;

    let index_path =
        std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());

    let file = match File::open(&index_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);

    let mut stats: BTreeMap<(String, String), (u64, u64)> = BTreeMap::new();

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: DigIndexEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let tenant = entry.tenant_id.unwrap_or_default();
        if let Some(tid) = tenant_filter {
            if tenant.as_str() != tid {
                continue;
            }
        }

        let key = (tenant, entry.root_id.clone());
        let e = stats.entry(key).or_insert((0, 0));
        e.0 += 1; // file_count
        if entry.time_end > e.1 {
            e.1 = entry.time_end;
        }
    }

    let mut rows = Vec::new();
    for ((tenant, root_id), (file_count, latest_time_end)) in stats {
        rows.push(DigCoverageRow {
            tenant_id: tenant,
            root_id,
            file_count,
            latest_time_end,
        });
    }

    Ok(rows)
}
