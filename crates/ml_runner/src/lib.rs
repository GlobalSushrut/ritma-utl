use common_models::{MLModels, MLScore, NGramResult, WindowRange, IFResult};
use security_interfaces::{MlRunner, Result, SecIfError};

pub struct SimpleCpuMl;

impl SimpleCpuMl {
    pub fn new() -> Self { Self }
}

impl MlRunner for SimpleCpuMl {
    fn score_window(&self, namespace_id: &str, window: &WindowRange, features: &serde_json::Value) -> Result<MLScore> {
        // Explainable, bounded heuristic as placeholder for CPU IsolationForest + n-gram
        let proc_execs = features.get("PROC_EXEC").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
        let net_new = features.get("NET_NEW_DESTS").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
        let burst = features.get("AUTH_FAIL_BURST").and_then(|v| v.as_u64()).unwrap_or(0) as f64;

        // Isolation-forest-ish surrogate (bounded)
        let if_score = ((proc_execs * 0.03) + (net_new * 0.06) + (burst * 0.09)).min(1.0);

        // N-gram surrogate: if NET+PROC present, raise suspicion modestly
        let ng_score = if net_new > 0.0 && proc_execs > 0.0 { 0.4 + (net_new * 0.02).min(0.6) } else { 0.1 };

        let iforest = IFResult {
            score: if_score,
            top_features: vec![
                ("new_egress".to_string(), (net_new * 0.3).min(0.3)),
                ("proc_exec".to_string(), (proc_execs * 0.2).min(0.2)),
                ("auth_burst".to_string(), (burst * 0.2).min(0.2)),
            ],
        };

        let ngram = NGramResult {
            score: ng_score,
            top_ngrams: vec![
                "PROC_EXEC->NET_CONNECT".to_string(),
                "AUTH_FAIL_BURST->PROC_EXEC_NEW".to_string(),
            ],
        };

        let final_ml = (0.6 * iforest.score + 0.4 * ngram.score).min(1.0);

        Ok(MLScore {
            ml_id: format!("ml_{}", uuid::Uuid::new_v4()),
            namespace_id: namespace_id.to_string(),
            window: window.clone(),
            models: MLModels { iforest: Some(iforest), ngram: Some(ngram) },
            final_ml_score: final_ml,
            explain: "CPU-only heuristic stub: burst+new egress + proc sequence".to_string(),
            range_used: serde_json::json!({"model":"cpu_stub_v1"}),
        })
    }
}
