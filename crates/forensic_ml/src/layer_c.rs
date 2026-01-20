//! Layer C: Behavior Similarity Embeddings
//!
//! Embeddings for clustering and similarity analysis:
//! - Graph embeddings
//! - Sequence embeddings
//! - All with versioned hashes for provenance

use crate::ModelVersions;
use common_models::TraceEvent;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Behavior embedding results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEmbedding {
    /// Embedding hash for provenance
    pub embedding_hash: String,
    /// Model version used
    pub model_version: String,
    /// Similarity risk score (0.0-1.0)
    pub similarity_risk: f64,

    /// Graph embedding
    pub graph_embedding: GraphEmbedding,
    /// Sequence embedding
    pub sequence_embedding: SequenceEmbedding,

    /// Similar known patterns
    pub similar_patterns: Vec<SimilarPattern>,
    /// Distance metrics
    pub distance_metrics: DistanceMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEmbedding {
    /// Embedding vector (reduced dimensionality)
    pub vector: Vec<f64>,
    /// Embedding dimension
    pub dimension: usize,
    /// Graph structure hash
    pub structure_hash: String,
    /// Node count
    pub node_count: usize,
    /// Edge count
    pub edge_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceEmbedding {
    /// Embedding vector
    pub vector: Vec<f64>,
    /// Sequence length
    pub sequence_length: usize,
    /// N-gram hash
    pub ngram_hash: String,
    /// Top n-grams
    pub top_ngrams: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarPattern {
    /// Pattern ID
    pub pattern_id: String,
    /// Pattern name/description
    pub pattern_name: String,
    /// Similarity score (0.0-1.0)
    pub similarity: f64,
    /// Pattern category (malware, normal, suspicious)
    pub category: String,
    /// Distance in embedding space
    pub distance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistanceMetrics {
    /// Euclidean distance to normal centroid
    pub euclidean_to_normal: f64,
    /// Cosine similarity to normal centroid
    pub cosine_to_normal: f64,
    /// Euclidean distance to malware centroid
    pub euclidean_to_malware: f64,
    /// Cosine similarity to malware centroid
    pub cosine_to_malware: f64,
}

/// Compute behavior embeddings from events and attack graph
pub fn compute_embeddings(
    events: &[TraceEvent],
    attack_graph: &serde_json::Value,
    model_versions: &ModelVersions,
) -> BehaviorEmbedding {
    // Graph embedding
    let graph_embedding = compute_graph_embedding(attack_graph, &model_versions.graph_embedding);

    // Sequence embedding
    let sequence_embedding = compute_sequence_embedding(events, &model_versions.sequence_embedding);

    // Find similar patterns
    let similar_patterns = find_similar_patterns(&graph_embedding, &sequence_embedding);

    // Compute distance metrics
    let distance_metrics = compute_distance_metrics(&graph_embedding, &sequence_embedding);

    // Similarity risk: based on distance to malware vs normal
    let similarity_risk = compute_similarity_risk(&distance_metrics);

    // Combined embedding hash
    let embedding_hash = compute_embedding_hash(&graph_embedding, &sequence_embedding);

    BehaviorEmbedding {
        embedding_hash,
        model_version: format!(
            "{}+{}",
            model_versions.graph_embedding, model_versions.sequence_embedding
        ),
        similarity_risk,
        graph_embedding,
        sequence_embedding,
        similar_patterns,
        distance_metrics,
    }
}

fn compute_graph_embedding(
    attack_graph: &serde_json::Value,
    model_version: &str,
) -> GraphEmbedding {
    let mut node_count = 0;
    let mut edge_count = 0;
    let mut edge_types: HashMap<String, usize> = HashMap::new();

    // Extract graph structure
    if let Some(edges) = attack_graph.get("edges").and_then(|e| e.as_array()) {
        edge_count = edges.len();
        let mut nodes: std::collections::HashSet<String> = std::collections::HashSet::new();

        for edge in edges {
            if let Some(src) = edge.get("src").and_then(|s| s.as_str()) {
                nodes.insert(src.to_string());
            }
            if let Some(dst) = edge.get("dst").and_then(|d| d.as_str()) {
                nodes.insert(dst.to_string());
            }
            if let Some(etype) = edge.get("type").and_then(|t| t.as_str()) {
                *edge_types.entry(etype.to_string()).or_insert(0) += 1;
            }
        }
        node_count = nodes.len();
    }

    // Create embedding vector (simplified graph2vec-style)
    // In production, this would use trained GNN or graph kernel
    let mut vector = vec![0.0; 16];

    // Feature 0-3: Graph size features
    vector[0] = (node_count as f64).ln().max(0.0) / 10.0;
    vector[1] = (edge_count as f64).ln().max(0.0) / 10.0;
    vector[2] = if node_count > 0 {
        edge_count as f64 / node_count as f64
    } else {
        0.0
    };
    vector[3] = (edge_types.len() as f64) / 10.0;

    // Feature 4-7: Edge type distribution
    let edge_type_keys = ["proc_spawn", "net_connect", "file_access", "priv_escalate"];
    for (i, key) in edge_type_keys.iter().enumerate() {
        vector[4 + i] = *edge_types.get(*key).unwrap_or(&0) as f64 / edge_count.max(1) as f64;
    }

    // Feature 8-15: Random walk features (simplified)
    for i in 8..16 {
        vector[i] = (node_count as f64 * (i - 7) as f64 / 100.0).sin().abs();
    }

    // Structure hash
    let structure_hash = {
        let mut h = Sha256::new();
        h.update(model_version.as_bytes());
        h.update(node_count.to_le_bytes());
        h.update(edge_count.to_le_bytes());
        for (k, v) in &edge_types {
            h.update(k.as_bytes());
            h.update(v.to_le_bytes());
        }
        hex::encode(h.finalize())
    };

    GraphEmbedding {
        vector,
        dimension: 16,
        structure_hash,
        node_count,
        edge_count,
    }
}

fn compute_sequence_embedding(events: &[TraceEvent], model_version: &str) -> SequenceEmbedding {
    // Build event sequence
    let mut sequence: Vec<String> = Vec::new();
    let mut ngram_counts: HashMap<String, usize> = HashMap::new();

    for ev in events {
        let event_type = format!("{:?}", ev.kind);
        sequence.push(event_type);
    }

    // Count 2-grams and 3-grams
    for window in sequence.windows(2) {
        let ngram = format!("{}→{}", window[0], window[1]);
        *ngram_counts.entry(ngram).or_insert(0) += 1;
    }
    for window in sequence.windows(3) {
        let ngram = format!("{}→{}→{}", window[0], window[1], window[2]);
        *ngram_counts.entry(ngram).or_insert(0) += 1;
    }

    // Top n-grams
    let mut top_ngrams: Vec<(String, usize)> =
        ngram_counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
    top_ngrams.sort_by(|a, b| b.1.cmp(&a.1));
    top_ngrams.truncate(10);

    // Create embedding vector (simplified sequence embedding)
    let mut vector = vec![0.0; 16];

    // Feature 0-3: Sequence statistics
    vector[0] = (sequence.len() as f64).ln().max(0.0) / 10.0;
    vector[1] = ngram_counts.len() as f64 / sequence.len().max(1) as f64;

    // Feature 4-9: Event type distribution
    let event_types = [
        "ProcExec",
        "NetConnect",
        "FileOpen",
        "DnsQuery",
        "Auth",
        "PrivChange",
    ];
    for (i, etype) in event_types.iter().enumerate() {
        let count = sequence.iter().filter(|e| e.contains(etype)).count();
        vector[4 + i] = count as f64 / sequence.len().max(1) as f64;
    }

    // Feature 10-15: N-gram features
    for (i, (_, count)) in top_ngrams.iter().take(6).enumerate() {
        vector[10 + i] = (*count as f64 / sequence.len().max(1) as f64).min(1.0);
    }

    // N-gram hash
    let ngram_hash = {
        let mut h = Sha256::new();
        h.update(model_version.as_bytes());
        for (ngram, count) in &top_ngrams {
            h.update(ngram.as_bytes());
            h.update(count.to_le_bytes());
        }
        hex::encode(h.finalize())
    };

    SequenceEmbedding {
        vector,
        sequence_length: sequence.len(),
        ngram_hash,
        top_ngrams,
    }
}

fn find_similar_patterns(
    graph_emb: &GraphEmbedding,
    seq_emb: &SequenceEmbedding,
) -> Vec<SimilarPattern> {
    // Known pattern centroids (in production, loaded from trained model)
    let known_patterns = vec![
        (
            "normal_web_app",
            "Normal Web Application",
            [0.1, 0.1, 0.3, 0.1],
            "normal",
        ),
        (
            "data_exfil",
            "Data Exfiltration Pattern",
            [0.3, 0.5, 0.7, 0.2],
            "malware",
        ),
        (
            "lateral_move",
            "Lateral Movement",
            [0.4, 0.3, 0.2, 0.5],
            "suspicious",
        ),
        (
            "crypto_miner",
            "Cryptominer Pattern",
            [0.8, 0.1, 0.1, 0.6],
            "malware",
        ),
        (
            "normal_batch",
            "Normal Batch Processing",
            [0.2, 0.2, 0.4, 0.1],
            "normal",
        ),
    ];

    let mut patterns = Vec::new();

    for (id, name, centroid, category) in known_patterns {
        // Compute distance (simplified)
        let mut dist = 0.0;
        for i in 0..4 {
            let g_val = graph_emb.vector.get(i).copied().unwrap_or(0.0);
            dist += (g_val - centroid[i]).powi(2);
        }
        dist = dist.sqrt();

        let similarity = (1.0 - dist / 2.0).clamp(0.0, 1.0);

        if similarity > 0.3 {
            patterns.push(SimilarPattern {
                pattern_id: id.to_string(),
                pattern_name: name.to_string(),
                similarity,
                category: category.to_string(),
                distance: dist,
            });
        }
    }

    patterns.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());
    patterns.truncate(5);
    patterns
}

fn compute_distance_metrics(
    graph_emb: &GraphEmbedding,
    seq_emb: &SequenceEmbedding,
) -> DistanceMetrics {
    // Normal centroid (simplified baseline)
    let normal_centroid: Vec<f64> = vec![
        0.1, 0.1, 0.3, 0.1, 0.2, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1,
    ];

    // Malware centroid
    let malware_centroid: Vec<f64> = vec![
        0.4, 0.5, 0.6, 0.3, 0.1, 0.4, 0.3, 0.5, 0.3, 0.4, 0.5, 0.4, 0.3, 0.2, 0.4, 0.5,
    ];

    // Combined embedding
    let combined: Vec<f64> = graph_emb
        .vector
        .iter()
        .zip(seq_emb.vector.iter())
        .map(|(g, s)| (g + s) / 2.0)
        .collect();

    // Euclidean distances
    let euclidean_to_normal = euclidean_distance(&combined, &normal_centroid);
    let euclidean_to_malware = euclidean_distance(&combined, &malware_centroid);

    // Cosine similarities
    let cosine_to_normal = cosine_similarity(&combined, &normal_centroid);
    let cosine_to_malware = cosine_similarity(&combined, &malware_centroid);

    DistanceMetrics {
        euclidean_to_normal,
        cosine_to_normal,
        euclidean_to_malware,
        cosine_to_malware,
    }
}

fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a.iter().map(|x| x.powi(2)).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| x.powi(2)).sum::<f64>().sqrt();

    if mag_a > 0.0 && mag_b > 0.0 {
        dot / (mag_a * mag_b)
    } else {
        0.0
    }
}

fn compute_similarity_risk(metrics: &DistanceMetrics) -> f64 {
    // Risk based on relative distance to malware vs normal
    let normal_score = metrics.cosine_to_normal;
    let malware_score = metrics.cosine_to_malware;

    // If closer to malware than normal, higher risk
    let relative_similarity = if normal_score + malware_score > 0.0 {
        malware_score / (normal_score + malware_score)
    } else {
        0.5
    };

    relative_similarity.clamp(0.0, 1.0)
}

fn compute_embedding_hash(graph: &GraphEmbedding, seq: &SequenceEmbedding) -> String {
    let mut h = Sha256::new();
    h.update(b"ritma-layer-c-embedding@0.1:");
    h.update(graph.structure_hash.as_bytes());
    h.update(seq.ngram_hash.as_bytes());
    for v in &graph.vector {
        h.update(v.to_le_bytes());
    }
    for v in &seq.vector {
        h.update(v.to_le_bytes());
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_euclidean_distance() {
        let a = vec![0.0, 0.0];
        let b = vec![3.0, 4.0];
        assert!((euclidean_distance(&a, &b) - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.001);
    }
}
