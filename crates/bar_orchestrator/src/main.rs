use std::thread::sleep;
use std::time::Duration;

use common_models::WindowRange;
use index_db::IndexDb;
use bar_orchestrator::Orchestrator;
use security_interfaces::PipelineOrchestrator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let namespace_id = std::env::var("NAMESPACE_ID").unwrap_or_else(|_| "ns://demo/dev/hello/world".to_string());
    let index_path = std::env::var("INDEX_DB_PATH").unwrap_or_else(|_| "/data/index_db.sqlite".to_string());
    let tick_secs: u64 = std::env::var("TICK_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);

    let index = IndexDb::open(&index_path)?;
    let orchestrator = Orchestrator::new(index);

    loop {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::seconds(tick_secs as i64);
        let window = WindowRange { start: start.to_rfc3339(), end: end.to_rfc3339() };
        match orchestrator.run_window(&namespace_id, &window) {
            Ok(proof) => eprintln!("orchestrator: sealed proof {}", proof.proof_id),
            Err(e) => eprintln!("orchestrator: error: {}", e),
        }
        sleep(Duration::from_secs(tick_secs));
    }
}
