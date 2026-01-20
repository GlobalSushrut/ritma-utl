use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentChainCount {
    pub parent_pid: i64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCoverage {
    pub proc_exec_count: u64,
    pub unique_binaries: u64,
    #[serde(default)]
    pub top_parent_chains: Vec<ParentChainCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionQuality {
    pub total: u64,
    pub attributed: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub version: String,
    pub namespace_id: String,
    pub window_start_ts: i64,
    pub window_end_ts: i64,
    pub process: ProcessCoverage,
    pub net_attribution: AttributionQuality,
}
