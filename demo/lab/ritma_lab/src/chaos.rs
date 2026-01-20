use anyhow::Result;
use std::collections::HashMap;
use tracing::info;
use ritma_lab_proto::ChaosAction;

pub struct ChaosController {
    scheduled: Vec<ChaosAction>,
    active: HashMap<String, ActiveChaos>,
}

struct ActiveChaos {
    action: ChaosAction,
    started_at: u32,
}

impl ChaosController {
    pub fn new() -> Self {
        Self {
            scheduled: Vec::new(),
            active: HashMap::new(),
        }
    }

    pub fn schedule(&mut self, action: ChaosAction) {
        info!(
            chaos_type = ?action.action,
            target = %action.target,
            start = action.start,
            "Scheduled chaos action"
        );
        self.scheduled.push(action);
    }

    pub async fn execute_in_range(&mut self, start: u32, end: u32) -> Result<()> {
        // Find actions that should start in this range
        let to_start: Vec<_> = self.scheduled
            .iter()
            .filter(|a| a.start >= start && a.start < end)
            .cloned()
            .collect();

        for action in to_start {
            self.inject(&action).await?;
        }

        // Find actions that should end in this range
        let to_end: Vec<_> = self.active
            .iter()
            .filter_map(|(id, ac)| {
                if let Some(duration) = ac.action.duration {
                    let end_time = ac.started_at + duration;
                    if end_time >= start && end_time < end {
                        return Some(id.clone());
                    }
                }
                None
            })
            .collect();

        for id in to_end {
            self.remove(&id).await?;
        }

        Ok(())
    }

    async fn inject(&mut self, action: &ChaosAction) -> Result<()> {
        let chaos_id = format!("chaos_{}", uuid::Uuid::now_v7());
        
        info!(
            chaos_id = %chaos_id,
            chaos_type = ?action.action,
            target = %action.target,
            "Injecting chaos"
        );

        // In a real implementation, this would use tc/iptables/cgroups
        // For now, we just log the action
        match action.action {
            ritma_lab_proto::ChaosType::Latency => {
                let latency_ms = action.params.get("latency_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100);
                info!(target = %action.target, latency_ms, "Simulating latency injection");
            }
            ritma_lab_proto::ChaosType::PacketLoss => {
                let percent = action.params.get("percent")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(10.0);
                info!(target = %action.target, percent, "Simulating packet loss");
            }
            ritma_lab_proto::ChaosType::Down => {
                info!(target = %action.target, "Simulating node down");
            }
            ritma_lab_proto::ChaosType::Restart => {
                let downtime = action.params.get("downtime_seconds")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(5);
                info!(target = %action.target, downtime, "Simulating restart");
            }
            _ => {
                info!(chaos_type = ?action.action, "Simulating chaos");
            }
        }

        self.active.insert(chaos_id, ActiveChaos {
            action: action.clone(),
            started_at: action.start,
        });

        Ok(())
    }

    async fn remove(&mut self, chaos_id: &str) -> Result<()> {
        if let Some(ac) = self.active.remove(chaos_id) {
            info!(
                chaos_id = %chaos_id,
                chaos_type = ?ac.action.action,
                target = %ac.action.target,
                "Removing chaos"
            );
        }
        Ok(())
    }

    pub fn clear_all(&mut self) {
        self.scheduled.clear();
        self.active.clear();
        info!("Cleared all chaos actions");
    }
}

impl Default for ChaosController {
    fn default() -> Self {
        Self::new()
    }
}
