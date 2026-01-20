use anyhow::Result;
use tracing::info;

use ritma_lab_proto::{Event, EventKind, Timestamp, NodeState};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("ritma_lab_node=info")
        .init();

    let node_id = std::env::var("NODE_ID").unwrap_or_else(|_| "unknown".to_string());
    let node_role = std::env::var("NODE_ROLE").unwrap_or_else(|_| "generic".to_string());

    info!(node_id = %node_id, role = %node_role, "Starting node runtime");

    // Simple node runtime - in production this would connect to orchestrator
    let mut sequence = 0u64;
    let mut state = NodeState::Ready;

    info!("Node ready, waiting for commands...");

    // Main loop
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal");
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                // Heartbeat
                sequence += 1;
                if sequence % 10 == 0 {
                    info!(sequence, state = ?state, "Heartbeat");
                }
            }
        }
    }

    info!("Node shutdown complete");
    Ok(())
}
