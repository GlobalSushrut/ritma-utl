//! Layer A: Deterministic Feature Core (Non-ML)
//!
//! These features are mathematically reproducible and explainable:
//! - Process graph structure metrics
//! - Temporal causality chains
//! - Entropy / rarity scores
//! - Privilege transition patterns
//! - IO / syscall flow invariants

use common_models::TraceEvent;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Deterministic features extracted from events and attack graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterministicFeatures {
    /// Feature hash (for provenance)
    pub feature_hash: String,
    /// Overall risk score from deterministic analysis
    pub risk_score: f64,
    /// Number of evidence items
    pub evidence_count: usize,

    /// Top contributing features (name -> score)
    pub top_features: Vec<(String, f64)>,

    /// Process graph metrics
    pub process_graph: ProcessGraphMetrics,
    /// Temporal causality
    pub temporal_causality: TemporalCausalityMetrics,
    /// Entropy scores
    pub entropy: EntropyMetrics,
    /// Privilege transitions
    pub privilege_transitions: PrivilegeMetrics,
    /// IO flow invariants
    pub io_flow: IOFlowMetrics,

    /// Anomalous edges detected
    pub anomalous_edges: Vec<AnomalousEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessGraphMetrics {
    /// Total process count
    pub process_count: usize,
    /// Maximum process tree depth
    pub max_depth: usize,
    /// Process diversity (unique commands)
    pub diversity: f64,
    /// Orphan process count
    pub orphan_count: usize,
    /// Fork bomb indicator (high fan-out)
    pub fork_fan_out: f64,
    /// Novel process lineage count
    pub novel_lineage: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalCausalityMetrics {
    /// Events in causal order
    pub causal_chain_length: usize,
    /// Timing anomalies (events out of expected order)
    pub timing_anomalies: usize,
    /// Burst events (many events in short time)
    pub burst_score: f64,
    /// Time between first and last event
    pub window_duration_secs: f64,
    /// Events per second
    pub event_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyMetrics {
    /// Command entropy (diversity of commands)
    pub command_entropy: f64,
    /// Path entropy (diversity of file paths)
    pub path_entropy: f64,
    /// Network destination entropy
    pub network_entropy: f64,
    /// Rarity score (how unusual are the patterns)
    pub rarity_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeMetrics {
    /// Privilege escalation count (uid 0 transitions)
    pub escalation_count: usize,
    /// Privilege drop count
    pub drop_count: usize,
    /// Setuid execution count
    pub setuid_count: usize,
    /// Root process count
    pub root_process_count: usize,
    /// Privilege transition score
    pub transition_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOFlowMetrics {
    /// File operations count
    pub file_ops: usize,
    /// Network connections count
    pub net_connections: usize,
    /// Novel network destinations
    pub novel_destinations: usize,
    /// Data exfiltration indicator
    pub exfil_indicator: f64,
    /// Sensitive file access count
    pub sensitive_access: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalousEdge {
    pub edge_type: String,
    pub src: String,
    pub dst: String,
    pub anomaly_score: f64,
    pub reason: String,
}

/// Extract deterministic features from events and attack graph
pub fn extract_deterministic_features(
    events: &[TraceEvent],
    attack_graph: &serde_json::Value,
) -> DeterministicFeatures {
    let process_graph = extract_process_graph_metrics(events);
    let temporal_causality = extract_temporal_causality(events);
    let entropy = extract_entropy_metrics(events);
    let privilege_transitions = extract_privilege_metrics(events);
    let io_flow = extract_io_flow_metrics(events);
    let anomalous_edges = extract_anomalous_edges(attack_graph);

    // Compute overall risk score (deterministic formula)
    let risk_score = compute_risk_score(
        &process_graph,
        &temporal_causality,
        &entropy,
        &privilege_transitions,
        &io_flow,
    );

    // Build top features
    let mut top_features = vec![
        ("process_diversity".to_string(), process_graph.diversity),
        ("burst_score".to_string(), temporal_causality.burst_score),
        ("command_entropy".to_string(), entropy.command_entropy),
        (
            "priv_transition".to_string(),
            privilege_transitions.transition_score,
        ),
        ("exfil_indicator".to_string(), io_flow.exfil_indicator),
        ("fork_fan_out".to_string(), process_graph.fork_fan_out),
        ("rarity_score".to_string(), entropy.rarity_score),
    ];
    top_features.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    top_features.truncate(7);

    // Compute feature hash
    let feature_hash = compute_feature_hash(events);

    DeterministicFeatures {
        feature_hash,
        risk_score,
        evidence_count: events.len(),
        top_features,
        process_graph,
        temporal_causality,
        entropy,
        privilege_transitions,
        io_flow,
        anomalous_edges,
    }
}

fn extract_process_graph_metrics(events: &[TraceEvent]) -> ProcessGraphMetrics {
    let mut pids: HashSet<i64> = HashSet::new();
    let mut ppids: HashSet<i64> = HashSet::new();
    let mut commands: HashSet<String> = HashSet::new();
    let mut pid_to_ppid: HashMap<i64, i64> = HashMap::new();
    let mut pid_children: HashMap<i64, usize> = HashMap::new();

    for ev in events {
        pids.insert(ev.actor.pid);
        ppids.insert(ev.actor.ppid);
        pid_to_ppid.insert(ev.actor.pid, ev.actor.ppid);
        *pid_children.entry(ev.actor.ppid).or_insert(0) += 1;

        if let Some(ref comm) = ev.actor.comm_hash {
            commands.insert(comm.clone());
        }
    }

    // Calculate max depth
    let max_depth = calculate_max_depth(&pid_to_ppid);

    // Orphan processes (ppid not in pids and ppid != 1)
    let orphan_count = ppids
        .iter()
        .filter(|&&ppid| ppid != 1 && !pids.contains(&ppid))
        .count();

    // Fork fan-out (max children / total processes)
    let max_children = pid_children.values().max().copied().unwrap_or(0);
    let fork_fan_out = if pids.is_empty() {
        0.0
    } else {
        max_children as f64 / pids.len() as f64
    };

    // Process diversity
    let diversity = if pids.is_empty() {
        0.0
    } else {
        commands.len() as f64 / pids.len() as f64
    };

    ProcessGraphMetrics {
        process_count: pids.len(),
        max_depth,
        diversity,
        orphan_count,
        fork_fan_out,
        novel_lineage: commands.len(),
    }
}

fn calculate_max_depth(pid_to_ppid: &HashMap<i64, i64>) -> usize {
    let mut max_depth = 0;
    for pid in pid_to_ppid.keys() {
        let mut depth = 0;
        let mut current = *pid;
        let mut visited: HashSet<i64> = HashSet::new();

        while let Some(&ppid) = pid_to_ppid.get(&current) {
            if visited.contains(&current) || depth > 100 {
                break;
            }
            visited.insert(current);
            current = ppid;
            depth += 1;
        }
        max_depth = max_depth.max(depth);
    }
    max_depth
}

fn extract_temporal_causality(events: &[TraceEvent]) -> TemporalCausalityMetrics {
    if events.is_empty() {
        return TemporalCausalityMetrics {
            causal_chain_length: 0,
            timing_anomalies: 0,
            burst_score: 0.0,
            window_duration_secs: 0.0,
            event_rate: 0.0,
        };
    }

    // Parse timestamps
    let mut timestamps: Vec<i64> = events
        .iter()
        .filter_map(|e| chrono::DateTime::parse_from_rfc3339(&e.ts).ok())
        .map(|t| t.timestamp_millis())
        .collect();
    timestamps.sort();

    let timing_anomalies = 0; // Would detect out-of-order events

    let window_duration_secs = if timestamps.len() >= 2 {
        (timestamps.last().unwrap() - timestamps.first().unwrap()) as f64 / 1000.0
    } else {
        0.0
    };

    let event_rate = if window_duration_secs > 0.0 {
        events.len() as f64 / window_duration_secs
    } else {
        events.len() as f64
    };

    // Burst detection (>10 events per second)
    let burst_score = (event_rate / 10.0).min(1.0);

    TemporalCausalityMetrics {
        causal_chain_length: events.len(),
        timing_anomalies,
        burst_score,
        window_duration_secs,
        event_rate,
    }
}

fn extract_entropy_metrics(events: &[TraceEvent]) -> EntropyMetrics {
    let mut commands: HashMap<String, usize> = HashMap::new();
    let mut paths: HashMap<String, usize> = HashMap::new();
    let mut destinations: HashMap<String, usize> = HashMap::new();

    for ev in events {
        if let Some(ref comm) = ev.actor.comm_hash {
            *commands.entry(comm.clone()).or_insert(0) += 1;
        }
        if let Some(ref path) = ev.target.path_hash {
            *paths.entry(path.clone()).or_insert(0) += 1;
        }
        if let Some(ref domain) = ev.target.domain_hash {
            *destinations.entry(domain.clone()).or_insert(0) += 1;
        }
    }

    let command_entropy = calculate_entropy(&commands, events.len());
    let path_entropy = calculate_entropy(&paths, events.len());
    let network_entropy = calculate_entropy(&destinations, events.len());

    // Rarity: high entropy + low count = rare patterns
    let rarity_score = ((command_entropy + path_entropy + network_entropy) / 3.0).min(1.0);

    EntropyMetrics {
        command_entropy,
        path_entropy,
        network_entropy,
        rarity_score,
    }
}

fn calculate_entropy(counts: &HashMap<String, usize>, total: usize) -> f64 {
    if total == 0 || counts.is_empty() {
        return 0.0;
    }

    let mut entropy = 0.0;
    for &count in counts.values() {
        if count > 0 {
            let p = count as f64 / total as f64;
            entropy -= p * p.log2();
        }
    }

    // Normalize to 0-1
    let max_entropy = (counts.len() as f64).log2();
    if max_entropy > 0.0 {
        entropy / max_entropy
    } else {
        0.0
    }
}

fn extract_privilege_metrics(events: &[TraceEvent]) -> PrivilegeMetrics {
    let mut escalation_count = 0;
    let mut drop_count = 0;
    let mut setuid_count = 0;
    let mut root_process_count = 0;
    let mut prev_uid: Option<i64> = None;

    for ev in events {
        if ev.actor.uid == 0 {
            root_process_count += 1;
        }

        if let Some(prev) = prev_uid {
            if prev != 0 && ev.actor.uid == 0 {
                escalation_count += 1;
            }
            if prev == 0 && ev.actor.uid != 0 {
                drop_count += 1;
            }
        }

        if ev.kind == common_models::TraceEventKind::PrivChange {
            setuid_count += 1;
        }

        prev_uid = Some(ev.actor.uid);
    }

    // Transition score: escalations are more suspicious
    let transition_score = if events.is_empty() {
        0.0
    } else {
        (escalation_count as f64 * 2.0 + setuid_count as f64) / events.len() as f64
    }
    .min(1.0);

    PrivilegeMetrics {
        escalation_count,
        drop_count,
        setuid_count,
        root_process_count,
        transition_score,
    }
}

fn extract_io_flow_metrics(events: &[TraceEvent]) -> IOFlowMetrics {
    let mut file_ops = 0;
    let mut net_connections = 0;
    let mut destinations: HashSet<String> = HashSet::new();
    let mut sensitive_access = 0;
    let mut total_bytes_out: i64 = 0;

    let sensitive_paths = ["/etc/passwd", "/etc/shadow", ".ssh", ".aws", ".kube"];

    for ev in events {
        match ev.kind {
            common_models::TraceEventKind::FileOpen => {
                file_ops += 1;
                if let Some(ref path) = ev.target.path_hash {
                    for sp in &sensitive_paths {
                        if path.contains(sp) {
                            sensitive_access += 1;
                            break;
                        }
                    }
                }
            }
            common_models::TraceEventKind::NetConnect => {
                net_connections += 1;
                if let Some(ref domain) = ev.target.domain_hash {
                    destinations.insert(domain.clone());
                }
            }
            _ => {}
        }

        if let Some(bytes) = ev.attrs.bytes_out {
            total_bytes_out += bytes;
        }
    }

    // Exfiltration indicator: high bytes out + network connections
    let exfil_indicator = if net_connections > 0 {
        ((total_bytes_out as f64 / 1_000_000.0) + (destinations.len() as f64 * 0.1)).min(1.0)
    } else {
        0.0
    };

    IOFlowMetrics {
        file_ops,
        net_connections,
        novel_destinations: destinations.len(),
        exfil_indicator,
        sensitive_access,
    }
}

fn extract_anomalous_edges(attack_graph: &serde_json::Value) -> Vec<AnomalousEdge> {
    let mut edges = Vec::new();

    if let Some(graph_edges) = attack_graph.get("edges").and_then(|e| e.as_array()) {
        for edge in graph_edges {
            let edge_type = edge
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            let src = edge.get("src").and_then(|s| s.as_str()).unwrap_or("");
            let dst = edge.get("dst").and_then(|d| d.as_str()).unwrap_or("");
            let score = edge.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0);

            // Flag high-score edges as anomalous
            if score > 0.5 {
                edges.push(AnomalousEdge {
                    edge_type: edge_type.to_string(),
                    src: src.to_string(),
                    dst: dst.to_string(),
                    anomaly_score: score,
                    reason: format!("High-risk {edge_type} edge (score: {score:.2})"),
                });
            }
        }
    }

    edges
}

fn compute_risk_score(
    process_graph: &ProcessGraphMetrics,
    temporal: &TemporalCausalityMetrics,
    entropy: &EntropyMetrics,
    privilege: &PrivilegeMetrics,
    io_flow: &IOFlowMetrics,
) -> f64 {
    // Deterministic risk formula (versioned)
    let pg_score = (process_graph.fork_fan_out * 0.3
        + process_graph.diversity * 0.2
        + (process_graph.orphan_count as f64 * 0.1).min(0.3))
    .min(1.0);

    let tc_score = temporal.burst_score;

    let en_score = entropy.rarity_score;

    let pr_score = privilege.transition_score;

    let io_score =
        (io_flow.exfil_indicator * 0.5 + (io_flow.sensitive_access as f64 * 0.1).min(0.5)).min(1.0);

    // Weighted combination
    (pg_score * 0.20 + tc_score * 0.15 + en_score * 0.20 + pr_score * 0.25 + io_score * 0.20)
        .clamp(0.0, 1.0)
}

fn compute_feature_hash(events: &[TraceEvent]) -> String {
    let mut h = Sha256::new();
    h.update(b"ritma-layer-a-features@0.1:");
    h.update(events.len().to_le_bytes());

    for ev in events {
        h.update(ev.namespace_id.as_bytes());
        h.update(ev.ts.as_bytes());
        h.update(ev.actor.pid.to_le_bytes());
    }

    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let mut counts = HashMap::new();
        counts.insert("a".to_string(), 5);
        counts.insert("b".to_string(), 5);

        let entropy = calculate_entropy(&counts, 10);
        assert!(entropy > 0.9, "Equal distribution should have high entropy");
    }

    #[test]
    fn test_empty_events() {
        let features = extract_deterministic_features(&[], &serde_json::json!({}));
        assert_eq!(features.evidence_count, 0);
        assert_eq!(features.risk_score, 0.0);
    }
}
