use common_models::{TraceEvent, TraceEventKind, WindowRange};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowFeatures {
    // Event counts
    pub proc_exec_count: u64,
    pub net_connect_count: u64,
    pub file_open_count: u64,
    pub auth_attempt_count: u64,
    
    // Novelty metrics
    pub novel_egress_endpoints: u64,
    pub novel_processes: u64,
    pub novel_files: u64,
    
    // Burst metrics
    pub auth_fail_burst: bool,
    pub auth_fail_rate: f64,
    
    // Entropy metrics
    pub process_diversity: f64,
    pub endpoint_diversity: f64,
    
    // Lineage metrics
    pub novel_parent_child_pairs: u64,
    pub max_process_depth: u64,
    
    // Service drift
    pub service_drift_score: f64,
    
    // Raw counts for reference
    pub total_events: u64,
}

impl Default for WindowFeatures {
    fn default() -> Self {
        Self {
            proc_exec_count: 0,
            net_connect_count: 0,
            file_open_count: 0,
            auth_attempt_count: 0,
            novel_egress_endpoints: 0,
            novel_processes: 0,
            novel_files: 0,
            auth_fail_burst: false,
            auth_fail_rate: 0.0,
            process_diversity: 0.0,
            endpoint_diversity: 0.0,
            novel_parent_child_pairs: 0,
            max_process_depth: 0,
            service_drift_score: 0.0,
            total_events: 0,
        }
    }
}

pub struct WindowSummarizer {
    baseline_endpoints: HashSet<String>,
    baseline_processes: HashSet<String>,
    baseline_files: HashSet<String>,
}

impl WindowSummarizer {
    pub fn new() -> Self {
        Self {
            baseline_endpoints: HashSet::new(),
            baseline_processes: HashSet::new(),
            baseline_files: HashSet::new(),
        }
    }
    
    pub fn load_baselines(&mut self, namespace_id: &str) -> Result<(), String> {
        // Load historical baselines from previous windows
        // For now, initialize empty - will be populated from historical data
        Ok(())
    }
    
    pub fn extract_features(
        &mut self,
        namespace_id: &str,
        window: &WindowRange,
        events: &[TraceEvent],
    ) -> Result<WindowFeatures, String> {
        let mut features = WindowFeatures::default();
        features.total_events = events.len() as u64;
        
        // Track unique items in this window
        let mut window_endpoints = HashSet::new();
        let mut window_processes = HashSet::new();
        let mut window_files = HashSet::new();
        let mut parent_child_pairs = HashSet::new();
        let mut auth_failures = Vec::new();
        
        // First pass: count events and collect unique items
        for event in events {
            match event.kind {
                TraceEventKind::ProcExec => {
                    features.proc_exec_count += 1;
                    let proc_id = format!("{}:{}", event.actor.pid, event.actor.ppid);
                    window_processes.insert(proc_id.clone());
                    
                    // Track parent-child relationship
                    if event.actor.ppid > 0 {
                        parent_child_pairs.insert((event.actor.ppid, event.actor.pid));
                    }
                }
                TraceEventKind::NetConnect => {
                    features.net_connect_count += 1;
                    if let Some(dst) = &event.target.dst {
                        window_endpoints.insert(dst.clone());
                    } else if let Some(hash) = &event.target.domain_hash {
                        window_endpoints.insert(hash.clone());
                    }
                }
                TraceEventKind::FileOpen => {
                    features.file_open_count += 1;
                    if let Some(path_hash) = &event.target.path_hash {
                        window_files.insert(path_hash.clone());
                    }
                }
                TraceEventKind::Auth => {
                    features.auth_attempt_count += 1;
                    // Track timestamp for burst detection
                    auth_failures.push(event.ts.clone());
                }
                _ => {}
            }
        }
        
        // Calculate novelty metrics
        features.novel_egress_endpoints = window_endpoints
            .difference(&self.baseline_endpoints)
            .count() as u64;
        features.novel_processes = window_processes
            .difference(&self.baseline_processes)
            .count() as u64;
        features.novel_files = window_files
            .difference(&self.baseline_files)
            .count() as u64;
        
        // Calculate diversity (Shannon entropy approximation)
        features.process_diversity = self.calculate_diversity(window_processes.len());
        features.endpoint_diversity = self.calculate_diversity(window_endpoints.len());
        
        // Detect auth fail burst (>5 failures in <10 seconds)
        if auth_failures.len() > 5 {
            features.auth_fail_burst = true;
            features.auth_fail_rate = auth_failures.len() as f64 / 60.0; // per minute
        }
        
        // Calculate lineage metrics
        features.novel_parent_child_pairs = parent_child_pairs.len() as u64;
        features.max_process_depth = self.calculate_max_depth(&parent_child_pairs);
        
        // Service drift: ratio of novel to total
        let total_unique = window_endpoints.len() + window_processes.len() + window_files.len();
        let total_novel = features.novel_egress_endpoints + features.novel_processes + features.novel_files;
        features.service_drift_score = if total_unique > 0 {
            total_novel as f64 / total_unique as f64
        } else {
            0.0
        };
        
        // Update baselines for next window
        self.baseline_endpoints.extend(window_endpoints);
        self.baseline_processes.extend(window_processes);
        self.baseline_files.extend(window_files);
        
        Ok(features)
    }
    
    fn calculate_diversity(&self, unique_count: usize) -> f64 {
        // Simple diversity metric: log(unique_count + 1)
        ((unique_count + 1) as f64).ln()
    }
    
    fn calculate_max_depth(&self, pairs: &HashSet<(i64, i64)>) -> u64 {
        // Build process tree and find max depth
        let mut depths: HashMap<i64, u64> = HashMap::new();
        let mut max_depth = 0u64;
        
        // Simple BFS-like depth calculation
        for (parent, child) in pairs {
            let parent_depth = depths.get(parent).copied().unwrap_or(0);
            let child_depth = parent_depth + 1;
            depths.insert(*child, child_depth);
            max_depth = max_depth.max(child_depth);
        }
        
        max_depth
    }
    
    pub fn to_json(&self, features: &WindowFeatures) -> serde_json::Value {
        serde_json::json!({
            "PROC_EXEC": features.proc_exec_count,
            "NET_CONNECT": features.net_connect_count,
            "FILE_OPEN": features.file_open_count,
            "AUTH_ATTEMPT": features.auth_attempt_count,
            "NOVEL_EGRESS": features.novel_egress_endpoints,
            "NOVEL_PROCS": features.novel_processes,
            "NOVEL_FILES": features.novel_files,
            "AUTH_FAIL_BURST": features.auth_fail_burst,
            "AUTH_FAIL_RATE": features.auth_fail_rate,
            "PROC_DIVERSITY": features.process_diversity,
            "ENDPOINT_DIVERSITY": features.endpoint_diversity,
            "NOVEL_LINEAGE": features.novel_parent_child_pairs,
            "MAX_PROC_DEPTH": features.max_process_depth,
            "SERVICE_DRIFT": features.service_drift_score,
            "TOTAL_EVENTS": features.total_events,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_models::{TraceSourceKind, TraceActor, TraceTarget, TraceAttrs};
    
    #[test]
    fn test_feature_extraction() {
        let events = vec![
            TraceEvent {
                trace_id: "t1".to_string(),
                ts: "2024-01-01T00:00:00Z".to_string(),
                namespace_id: "ns://test".to_string(),
                source: TraceSourceKind::Auditd,
                kind: TraceEventKind::ProcExec,
                actor: TraceActor { pid: 100, ppid: 1, uid: 0, gid: 0, container_id: None, service: None, build_hash: None },
                target: TraceTarget { path_hash: None, dst: None, domain_hash: None },
                attrs: TraceAttrs { argv_hash: None, cwd_hash: None, bytes_out: None },
            },
            TraceEvent {
                trace_id: "t2".to_string(),
                ts: "2024-01-01T00:00:01Z".to_string(),
                namespace_id: "ns://test".to_string(),
                source: TraceSourceKind::Runtime,
                kind: TraceEventKind::NetConnect,
                actor: TraceActor { pid: 100, ppid: 1, uid: 0, gid: 0, container_id: None, service: None, build_hash: None },
                target: TraceTarget { path_hash: None, dst: Some("1.2.3.4:443".to_string()), domain_hash: None },
                attrs: TraceAttrs { argv_hash: None, cwd_hash: None, bytes_out: None },
            },
        ];
        
        let mut summarizer = WindowSummarizer::new();
        
        let window = WindowRange {
            start: "2024-01-01T00:00:00Z".to_string(),
            end: "2024-01-01T00:01:00Z".to_string(),
        };
        
        let features = summarizer.extract_features("ns://test", &window, &events).unwrap();
        
        assert_eq!(features.proc_exec_count, 1);
        assert_eq!(features.net_connect_count, 1);
        assert_eq!(features.total_events, 2);
        assert!(features.novel_egress_endpoints > 0);
    }
}
