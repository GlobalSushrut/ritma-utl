use std::fs::File;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::thread::sleep;
use std::time::Duration;

use bar_orchestrator::Orchestrator;
use common_models::WindowRange;
use index_db::IndexDb;
use ritma_contract::StorageContract;
use security_interfaces::PipelineOrchestrator;

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

fn acquire_single_instance_lock(contract: &StorageContract) -> Result<Option<File>, Box<dyn std::error::Error>> {
    if env_truthy("RITMA_ALLOW_MULTI_ORCHESTRATOR") {
        return Ok(None);
    }

    let lock_dir = &contract.lock_dir;
    let _ = std::fs::create_dir_all(lock_dir);
    let lock_path = contract.orchestrator_lock_path();

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)?;

    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(std::io::Error::other(format!(
                "bar_orchestrator already running (lock {}). To bypass single-writer lock set RITMA_ALLOW_MULTI_ORCHESTRATOR=1",
                lock_path.display()
            ))
            .into());
        }
        return Err(std::io::Error::other(format!(
            "failed to acquire bar_orchestrator lock {}: {e}. Check that lock dir exists and is writable (e.g. /run/ritma/locks)",
            lock_path.display()
        ))
        .into());
    }

    let _ = f.set_len(0);
    let _ = f.write_all(format!("pid={}\n", std::process::id()).as_bytes());
    let _ = f.flush();

    Ok(Some(f))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let namespace_id =
        std::env::var("NAMESPACE_ID").unwrap_or_else(|_| "ns://demo/dev/hello/world".to_string());

    let contract = StorageContract::resolve_cctv()?;

    let _lock = acquire_single_instance_lock(&contract)?;

    contract.ensure_base_dir()?;
    contract.ensure_out_layout()?;
    let index_path = contract.index_db_path.display().to_string();
    let tick_secs: u64 = std::env::var("TICK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    if let Some(parent) = contract.index_db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let index = IndexDb::open(&index_path)?;
    let orchestrator = Orchestrator::new(index);

    loop {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::seconds(tick_secs as i64);
        let window = WindowRange {
            start: start.to_rfc3339(),
            end: end.to_rfc3339(),
        };
        match orchestrator.run_window(&namespace_id, &window) {
            Ok(proof) => eprintln!("orchestrator: sealed proof {}", proof.proof_id),
            Err(e) => eprintln!("orchestrator: error: {e}"),
        }
        sleep(Duration::from_secs(tick_secs));
    }
}
