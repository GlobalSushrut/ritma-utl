use common_models::{TraceEvent, TraceEventKind, WindowRange};
use index_db::{IndexDb, AttackGraphEdgeRow};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    ProcToNet,      // Process → Network connection
    ProcToFile,     // Process → File access
    ProcToProc,     // Process → Process (parent-child)
    AuthEvent,      // Authentication event
    PrivEscalation, // Privilege change
    FileToProc,     // File → Process (loaded library/exec)
}

// Kinetic graph: behavioral velocity and intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralVelocity {
    pub events_per_second: f64,
    pub unique_targets_per_minute: f64,
    pub escalation_rate: f64,  // priv_esc events / total events
    pub lateral_movement_rate: f64,  // new network targets / time
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentAccumulation {
    pub recon_score: f64,      // file reads, network scans
    pub access_score: f64,     // file writes, auth attempts
    pub exfil_score: f64,      // network egress, large transfers
    pub persist_score: f64,    // cron, systemd, autostart
    pub total_intent: f64,     // weighted sum
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationTrajectory {
    pub direction: String,     // "ascending", "lateral", "descending"
    pub velocity: f64,         // rate of privilege/access change
    pub target_drift: f64,     // how far from baseline targets
    pub anomaly_momentum: f64, // acceleration of anomalous behavior
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossWindowContinuity {
    pub persistent_processes: Vec<String>,  // PIDs across windows
    pub recurring_targets: Vec<String>,     // IPs/files accessed repeatedly
    pub behavioral_drift: f64,              // score change vs previous window
    pub intent_carryover: f64,              // accumulated intent from prev windows
}

impl EdgeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EdgeType::ProcToNet => "PROC_NET",
            EdgeType::ProcToFile => "PROC_FILE",
            EdgeType::ProcToProc => "PROC_PROC",
            EdgeType::AuthEvent => "AUTH",
            EdgeType::PrivEscalation => "PRIV_ESC",
            EdgeType::FileToProc => "FILE_PROC",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraphEdge {
    pub edge_type: EdgeType,
    pub src: String,
    pub dst: String,
    pub attrs: serde_json::Value,
    pub timestamp: String,  // for temporal ordering
    pub weight: f64,        // intent weight (higher = more suspicious)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KineticGraph {
    pub structural_edges: Vec<AttackGraphEdge>,
    pub velocity: BehavioralVelocity,
    pub intent: IntentAccumulation,
    pub trajectory: EscalationTrajectory,
    pub continuity: Option<CrossWindowContinuity>,
    pub kinetic_hash: String,  // hash of velocity + intent + trajectory
}

pub struct AttackGraphBuilder {
    db: IndexDb,
}

impl AttackGraphBuilder {
    pub fn new(db: IndexDb) -> Self {
        Self { db }
    }
    
    pub fn build_graph(
        &self,
        namespace_id: &str,
        window: &WindowRange,
        events: &[TraceEvent],
    ) -> Result<(Vec<AttackGraphEdge>, String), String> {
        let mut edges = Vec::new();
        let mut process_map: HashMap<i64, String> = HashMap::new();
        
        for event in events {
            match event.kind {
                TraceEventKind::ProcExec => {
                    let proc_id = format!("proc:{}", event.actor.pid);
                    process_map.insert(event.actor.pid, proc_id.clone());
                    
                    // PROC_PROC edge (parent → child)
                    if event.actor.ppid > 0 {
                        let parent_id = process_map
                            .get(&event.actor.ppid)
                            .cloned()
                            .unwrap_or_else(|| format!("proc:{}", event.actor.ppid));
                        
                        edges.push(AttackGraphEdge {
                            edge_type: EdgeType::ProcToProc,
                            src: parent_id,
                            dst: proc_id.clone(),
                            attrs: serde_json::json!({
                                "pid": event.actor.pid,
                                "ppid": event.actor.ppid,
                                "uid": event.actor.uid,
                                "gid": event.actor.gid,
                                "ts": event.ts,
                                "argv_hash": event.attrs.argv_hash,
                            }),
                            timestamp: event.ts.clone(),
                            weight: 1.0,
                        });
                    }
                    
                    // Check for privilege escalation
                    if event.actor.uid == 0 && event.actor.ppid > 0 {
                        edges.push(AttackGraphEdge {
                            edge_type: EdgeType::PrivEscalation,
                            src: proc_id.clone(),
                            dst: "root".to_string(),
                            attrs: serde_json::json!({
                                "from_uid": "non-root",
                                "to_uid": 0,
                                "ts": event.ts,
                            }),
                            timestamp: event.ts.clone(),
                            weight: 3.0,  // High weight for priv esc
                        });
                    }
                }
                
                TraceEventKind::NetConnect => {
                    let proc_id = process_map
                        .get(&event.actor.pid)
                        .cloned()
                        .unwrap_or_else(|| format!("proc:{}", event.actor.pid));
                    
                    let endpoint = event.target.dst
                        .clone()
                        .or_else(|| event.target.domain_hash.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    
                    // PROC_NET edge
                    let weight = if !endpoint.starts_with("127.") && !endpoint.starts_with("192.168.") { 2.0 } else { 1.0 };
                    edges.push(AttackGraphEdge {
                        edge_type: EdgeType::ProcToNet,
                        src: proc_id,
                        dst: format!("net:{}", endpoint),
                        attrs: serde_json::json!({
                            "endpoint": endpoint,
                            "ts": event.ts,
                            "bytes_out": event.attrs.bytes_out,
                        }),
                        timestamp: event.ts.clone(),
                        weight,  // Higher weight for external IPs
                    });
                }
                
                TraceEventKind::FileOpen => {
                    let proc_id = process_map
                        .get(&event.actor.pid)
                        .cloned()
                        .unwrap_or_else(|| format!("proc:{}", event.actor.pid));
                    
                    let file_id = event.target.path_hash
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string());
                    
                    // PROC_FILE edge
                    edges.push(AttackGraphEdge {
                        edge_type: EdgeType::ProcToFile,
                        src: proc_id,
                        dst: format!("file:{}", file_id),
                        attrs: serde_json::json!({
                            "path_hash": file_id,
                            "ts": event.ts,
                        }),
                        timestamp: event.ts.clone(),
                        weight: 1.0,
                    });
                }
                
                TraceEventKind::Auth => {
                    let user_id = format!("user:{}", event.actor.uid);
                    // AUTH edge
                    edges.push(AttackGraphEdge {
                        edge_type: EdgeType::AuthEvent,
                        src: user_id,
                        dst: "auth_system".to_string(),
                        attrs: serde_json::json!({
                            "uid": event.actor.uid,
                            "ts": event.ts,
                        }),
                        timestamp: event.ts.clone(),
                        weight: 1.5,
                    });
                }
                
                _ => {}
            }
        }
        
        // Compute deterministic graph hash
        let graph_hash = self.compute_graph_hash(&edges);
        
        Ok((edges, graph_hash))
    }
    
    pub fn persist_graph(
        &self,
        window_id: &str,
        edges: &[AttackGraphEdge],
    ) -> Result<(), String> {
        for edge in edges {
            let row = AttackGraphEdgeRow {
                window_id: window_id.to_string(),
                edge_type: edge.edge_type.as_str().to_string(),
                src: edge.src.clone(),
                dst: edge.dst.clone(),
                attrs: edge.attrs.clone(),
            };
            
            self.db.insert_attack_graph_edge(&row)
                .map_err(|e| format!("insert edge: {}", e))?;
        }
        
        Ok(())
    }
    
    fn compute_graph_hash(&self, edges: &[AttackGraphEdge]) -> String {
        // Sort edges for deterministic hashing
        let mut sorted_edges: Vec<String> = edges.iter().map(|e| {
            format!("{}:{}:{}", e.edge_type.as_str(), e.src, e.dst)
        }).collect();
        sorted_edges.sort();
        
        let mut hasher = Sha256::new();
        for edge_str in sorted_edges {
            hasher.update(edge_str.as_bytes());
        }
        
        hex::encode(hasher.finalize())
    }
    
    pub fn get_edge_delta(
        &self,
        window_a: &str,
        window_b: &str,
    ) -> Result<(Vec<AttackGraphEdgeRow>, Vec<AttackGraphEdgeRow>), String> {
        let edges_a = self.db.list_edges(window_a)
            .map_err(|e| format!("list edges a: {}", e))?;
        let edges_b = self.db.list_edges(window_b)
            .map_err(|e| format!("list edges b: {}", e))?;
        
        // Find edges only in A (removed)
        let mut only_a = Vec::new();
        for edge_a in &edges_a {
            let found = edges_b.iter().any(|edge_b| {
                edge_a.edge_type == edge_b.edge_type &&
                edge_a.src == edge_b.src &&
                edge_a.dst == edge_b.dst
            });
            if !found {
                only_a.push(edge_a.clone());
            }
        }
        
        // Find edges only in B (added)
        let mut only_b = Vec::new();
        for edge_b in &edges_b {
            let found = edges_a.iter().any(|edge_a| {
                edge_a.edge_type == edge_b.edge_type &&
                edge_a.src == edge_b.src &&
                edge_a.dst == edge_b.dst
            });
            if !found {
                only_b.push(edge_b.clone());
            }
        }
        
        Ok((only_a, only_b))
    }
    
    // Compute kinetic metrics: behavioral velocity
    pub fn compute_velocity(&self, events: &[TraceEvent], window_duration_secs: f64) -> BehavioralVelocity {
        let total_events = events.len() as f64;
        let events_per_second = total_events / window_duration_secs.max(1.0);
        
        let mut unique_targets = std::collections::HashSet::new();
        let mut priv_esc_count = 0;
        let mut network_targets = std::collections::HashSet::new();
        
        for event in events {
            match event.kind {
                TraceEventKind::NetConnect => {
                    if let Some(endpoint) = event.target.dst.as_ref().or(event.target.domain_hash.as_ref()) {
                        unique_targets.insert(endpoint.clone());
                        network_targets.insert(endpoint.clone());
                    }
                }
                TraceEventKind::FileOpen => {
                    if let Some(path) = event.target.path_hash.as_ref() {
                        unique_targets.insert(path.clone());
                    }
                }
                TraceEventKind::ProcExec => {
                    if event.actor.uid == 0 {
                        priv_esc_count += 1;
                    }
                }
                _ => {}
            }
        }
        
        let unique_targets_per_minute = (unique_targets.len() as f64) / (window_duration_secs / 60.0).max(1.0);
        let escalation_rate = if total_events > 0.0 { priv_esc_count as f64 / total_events } else { 0.0 };
        let lateral_movement_rate = (network_targets.len() as f64) / (window_duration_secs / 60.0).max(1.0);
        
        BehavioralVelocity {
            events_per_second,
            unique_targets_per_minute,
            escalation_rate,
            lateral_movement_rate,
        }
    }
    
    // Compute intent accumulation
    pub fn compute_intent(&self, events: &[TraceEvent]) -> IntentAccumulation {
        let mut recon_score = 0.0;
        let mut access_score = 0.0;
        let mut exfil_score = 0.0;
        let mut persist_score = 0.0;
        
        for event in events {
            match event.kind {
                TraceEventKind::FileOpen => {
                    // Recon: reading sensitive files
                    if let Some(path) = event.target.path_hash.as_ref() {
                        if path.contains("/etc/") || path.contains("/proc/") || path.contains("/sys/") {
                            recon_score += 1.0;
                        }
                        if path.contains("cron") || path.contains("systemd") || path.contains(".bashrc") {
                            persist_score += 2.0;
                        }
                    }
                    access_score += 0.5;
                }
                TraceEventKind::NetConnect => {
                    // Exfil: external network connections
                    if let Some(endpoint) = event.target.dst.as_ref().or(event.target.domain_hash.as_ref()) {
                        if !endpoint.starts_with("127.") && !endpoint.starts_with("192.168.") {
                            exfil_score += 2.0;
                        }
                    }
                }
                TraceEventKind::Auth => {
                    access_score += 1.5;
                }
                TraceEventKind::ProcExec => {
                    if event.actor.uid == 0 {
                        access_score += 2.0;
                    }
                }
                _ => {}
            }
        }
        
        let total_intent = (recon_score * 0.2) + (access_score * 0.3) + (exfil_score * 0.4) + (persist_score * 0.1);
        
        IntentAccumulation {
            recon_score,
            access_score,
            exfil_score,
            persist_score,
            total_intent,
        }
    }
    
    // Compute escalation trajectory
    pub fn compute_trajectory(&self, events: &[TraceEvent], prev_score: Option<f64>, current_score: f64) -> EscalationTrajectory {
        let mut uid_changes = 0;
        let mut target_set = std::collections::HashSet::new();
        
        for event in events {
            if event.actor.uid == 0 {
                uid_changes += 1;
            }
            if let Some(endpoint) = event.target.dst.as_ref().or(event.target.domain_hash.as_ref()) {
                target_set.insert(endpoint.clone());
            }
            if let Some(path) = event.target.path_hash.as_ref() {
                target_set.insert(path.clone());
            }
        }
        
        let direction = if let Some(prev) = prev_score {
            if current_score > prev + 0.1 {
                "ascending".to_string()
            } else if current_score < prev - 0.1 {
                "descending".to_string()
            } else {
                "lateral".to_string()
            }
        } else {
            "baseline".to_string()
        };
        
        let velocity = if let Some(prev) = prev_score {
            (current_score - prev).abs()
        } else {
            0.0
        };
        
        let target_drift = target_set.len() as f64 / events.len().max(1) as f64;
        let anomaly_momentum = if velocity > 0.1 { velocity * 2.0 } else { 0.0 };
        
        EscalationTrajectory {
            direction,
            velocity,
            target_drift,
            anomaly_momentum,
        }
    }
    
    // Build complete kinetic graph
    pub fn build_kinetic_graph(
        &self,
        namespace_id: &str,
        window: &WindowRange,
        events: &[TraceEvent],
        window_duration_secs: f64,
        prev_score: Option<f64>,
        current_score: f64,
    ) -> Result<KineticGraph, String> {
        let (edges, _) = self.build_graph(namespace_id, window, events)?;
        
        let velocity = self.compute_velocity(events, window_duration_secs);
        let intent = self.compute_intent(events);
        let trajectory = self.compute_trajectory(events, prev_score, current_score);
        
        // Compute kinetic hash (velocity + intent + trajectory)
        let kinetic_data = format!("{:.3}|{:.3}|{:.3}|{:.3}|{}|{:.3}",
            velocity.events_per_second,
            velocity.escalation_rate,
            intent.total_intent,
            trajectory.velocity,
            trajectory.direction,
            trajectory.anomaly_momentum,
        );
        let mut hasher = Sha256::new();
        hasher.update(kinetic_data.as_bytes());
        let kinetic_hash = hex::encode(hasher.finalize());
        
        Ok(KineticGraph {
            structural_edges: edges,
            velocity,
            intent,
            trajectory,
            continuity: None,  // TODO: implement cross-window tracking
            kinetic_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_models::{TraceSourceKind, TraceActor, TraceTarget, TraceAttrs};
    
    #[test]
    fn test_graph_building() {
        let events = vec![
            TraceEvent {
                trace_id: "t1".to_string(),
                ts: "2024-01-01T00:00:00Z".to_string(),
                namespace_id: "ns://test".to_string(),
                source: TraceSourceKind::Auditd,
                kind: TraceEventKind::ProcExec,
                actor: TraceActor { pid: 100, ppid: 1, uid: 0, gid: 0, container_id: None, service: None, build_hash: None },
                target: TraceTarget { path_hash: None, dst: None, domain_hash: None },
                attrs: TraceAttrs { argv_hash: Some("hash123".to_string()), cwd_hash: None, bytes_out: None },
            },
            TraceEvent {
                trace_id: "t2".to_string(),
                ts: "2024-01-01T00:00:01Z".to_string(),
                namespace_id: "ns://test".to_string(),
                source: TraceSourceKind::Runtime,
                kind: TraceEventKind::NetConnect,
                actor: TraceActor { pid: 100, ppid: 1, uid: 0, gid: 0, container_id: None, service: None, build_hash: None },
                target: TraceTarget { path_hash: None, dst: Some("1.2.3.4:443".to_string()), domain_hash: None },
                attrs: TraceAttrs { argv_hash: None, cwd_hash: None, bytes_out: Some(1024) },
            },
        ];
        
        let db = IndexDb::open(":memory:").unwrap();
        let builder = AttackGraphBuilder::new(db);
        
        let window = WindowRange {
            start: "2024-01-01T00:00:00Z".to_string(),
            end: "2024-01-01T00:01:00Z".to_string(),
        };
        
        let (edges, hash) = builder.build_graph("ns://test", &window, &events).unwrap();
        
        assert!(edges.len() >= 2); // At least PROC_PROC and PROC_NET
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }
}
