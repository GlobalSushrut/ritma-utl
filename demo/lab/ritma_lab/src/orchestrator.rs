use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use ritma_lab_proto::{
    Topology, NodeSpec, Scenario, Phase,
    Event, EventKind,
    NodeState,
};

use crate::chaos::ChaosController;
use crate::traffic::TrafficGenerator;
use crate::evidence::EvidenceCollector;
use crate::ritma_integration::LabRitmaManager;

#[derive(Debug, Clone)]
pub struct LabState {
    pub status: LabStatus,
    pub run_id: String,
    pub start_time: Option<i64>,
    pub current_phase: Option<String>,
    pub events_collected: u64,
    pub windows_sealed: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LabStatus {
    Idle,
    Initializing,
    Running,
    Stopping,
    Stopped,
    Error(String),
}

pub struct NodeHandle {
    pub spec: NodeSpec,
    pub state: NodeState,
    pub events_generated: u64,
}

pub struct LabOrchestrator {
    topology: Option<Topology>,
    scenario: Option<Scenario>,
    nodes: HashMap<String, NodeHandle>,
    chaos_controller: ChaosController,
    traffic_generator: TrafficGenerator,
    evidence_collector: EvidenceCollector,
    ritma_manager: Option<LabRitmaManager>,
    state: Arc<RwLock<LabState>>,
    lab_dir: PathBuf,
    use_real_ritma: bool,
}

impl LabOrchestrator {
    pub fn new() -> Self {
        Self::with_config(PathBuf::from("."), false)
    }

    pub fn with_config(lab_dir: PathBuf, use_real_ritma: bool) -> Self {
        Self {
            topology: None,
            scenario: None,
            nodes: HashMap::new(),
            chaos_controller: ChaosController::new(),
            traffic_generator: TrafficGenerator::new(42),
            evidence_collector: EvidenceCollector::new(),
            ritma_manager: None,
            state: Arc::new(RwLock::new(LabState {
                status: LabStatus::Idle,
                run_id: String::new(),
                start_time: None,
                current_phase: None,
                events_collected: 0,
                windows_sealed: 0,
            })),
            lab_dir,
            use_real_ritma,
        }
    }

    pub async fn load_topology(&mut self, path: &str) -> Result<()> {
        let content = tokio::fs::read_to_string(path).await?;
        let topology: Topology = serde_yaml::from_str(&content)?;
        
        topology.validate().map_err(|e| anyhow::anyhow!(e))?;
        
        info!(
            name = %topology.metadata.name,
            nodes = topology.nodes.len(),
            "Loaded topology"
        );
        
        self.topology = Some(topology);
        Ok(())
    }

    pub async fn load_scenario(&mut self, path: &str) -> Result<()> {
        let content = tokio::fs::read_to_string(path).await?;
        let scenario: Scenario = serde_yaml::from_str(&content)?;
        
        scenario.validate().map_err(|e| anyhow::anyhow!(e))?;
        
        info!(
            name = %scenario.scenario.name,
            duration = scenario.scenario.duration_seconds,
            phases = scenario.phases.len(),
            "Loaded scenario"
        );
        
        self.scenario = Some(scenario);
        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        let topology = self.topology.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No topology loaded"))?;

        {
            let mut state = self.state.write().await;
            state.status = LabStatus::Initializing;
            state.run_id = topology.metadata.run_id.clone();
            state.start_time = Some(chrono::Utc::now().timestamp());
        }

        info!(run_id = %topology.metadata.run_id, use_real_ritma = self.use_real_ritma, "Starting lab");

        // Initialize real Ritma if enabled
        if self.use_real_ritma {
            let mut ritma_manager = LabRitmaManager::new(self.lab_dir.clone());
            for node_spec in &topology.nodes {
                if node_spec.ritma.enabled {
                    ritma_manager.init_node(&node_spec.id, &topology.metadata.name)?;
                    info!(node_id = %node_spec.id, "Initialized REAL Ritma agent");
                }
            }
            self.ritma_manager = Some(ritma_manager);
        }

        // Initialize nodes
        for node_spec in &topology.nodes {
            info!(node_id = %node_spec.id, role = ?node_spec.role, "Initializing node");
            
            self.nodes.insert(node_spec.id.clone(), NodeHandle {
                spec: node_spec.clone(),
                state: NodeState::Ready,
                events_generated: 0,
            });
        }

        // Start evidence collector
        self.evidence_collector.start(topology.aggregator.window_seconds).await?;

        {
            let mut state = self.state.write().await;
            state.status = LabStatus::Running;
        }

        info!("Lab started successfully");
        Ok(())
    }

    pub async fn run_scenario(&mut self) -> Result<()> {
        let scenario = self.scenario.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No scenario loaded"))?
            .clone();

        info!(name = %scenario.scenario.name, "Running scenario");

        let start_time = std::time::Instant::now();
        let duration = std::time::Duration::from_secs(scenario.scenario.duration_seconds as u64);

        // Schedule chaos actions
        for chaos in &scenario.chaos {
            self.chaos_controller.schedule(chaos.clone());
        }

        // Execute phases
        for phase in &scenario.phases {
            let phase_start = std::time::Duration::from_secs(phase.start as u64);
            
            // Wait for phase start
            let elapsed = start_time.elapsed();
            if elapsed < phase_start {
                tokio::time::sleep(phase_start - elapsed).await;
            }

            info!(phase = %phase.name, "Starting phase");
            
            {
                let mut state = self.state.write().await;
                state.current_phase = Some(phase.name.clone());
            }

            // Generate traffic for this phase
            if let Some(ref traffic) = phase.traffic {
                self.generate_phase_traffic(&phase, traffic.rps).await?;
            }

            // Trigger scripted events
            for event in &phase.events {
                self.trigger_scripted_event(event).await?;
            }

            // Check for chaos actions during this phase
            let phase_end = phase.start + phase.duration;
            self.chaos_controller.execute_in_range(phase.start, phase_end).await?;
        }

        // Wait for scenario to complete
        let elapsed = start_time.elapsed();
        if elapsed < duration {
            tokio::time::sleep(duration - elapsed).await;
        }

        // Seal final window
        self.evidence_collector.seal_window().await?;

        info!("Scenario completed");
        Ok(())
    }

    async fn generate_phase_traffic(&mut self, phase: &Phase, rps: u32) -> Result<()> {
        let events_to_generate = rps * phase.duration;
        let _interval = std::time::Duration::from_millis(1000 / rps.max(1) as u64);

        // Enable AI mode if traffic type is ai_inference
        if let Some(ref traffic) = phase.traffic {
            let is_ai = traffic.traffic_type == "ai_inference";
            self.traffic_generator.set_ai_mode(is_ai);
            if is_ai {
                if let Some(model) = traffic.params.get("model").and_then(|v| v.as_str()) {
                    let version = if model.contains("-v") {
                        model.rsplit("-").next().unwrap_or("v1")
                    } else { "v1" };
                    let model_id = model.split("-v").next().unwrap_or(model);
                    self.traffic_generator.set_model(model_id, version);
                }
            }
        }

        // Collect events per node for real Ritma windows
        let mut node_events: HashMap<String, Vec<Event>> = HashMap::new();
        let window_start = chrono::Utc::now().timestamp();

        for i in 0..events_to_generate {
            let node_ids: Vec<_> = self.nodes.keys().cloned().collect();
            if node_ids.is_empty() {
                continue;
            }

            let node_id = &node_ids[i as usize % node_ids.len()];
            
            if let Some(handle) = self.nodes.get_mut(node_id) {
                handle.events_generated += 1;
                
                let event = self.traffic_generator.generate_event(
                    node_id.clone(),
                    handle.events_generated,
                );
                
                // Record to simulated evidence collector
                self.evidence_collector.record_event(event.clone()).await?;
                
                // Collect for real Ritma
                node_events.entry(node_id.clone()).or_default().push(event);
            }

            if i % 10 == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }

        // Write real Ritma windows if enabled
        if let Some(ref mut ritma_manager) = self.ritma_manager {
            let window_end = chrono::Utc::now().timestamp();
            for (node_id, events) in &node_events {
                if !events.is_empty() {
                    ritma_manager.write_window(node_id, window_start, window_end, events)?;
                }
            }
        }

        Ok(())
    }

    async fn trigger_scripted_event(&mut self, event: &ritma_lab_proto::ScriptedEvent) -> Result<()> {
        info!(event_type = %event.event_type, "Triggering scripted event");

        // Generate custom event for all nodes
        for (node_id, handle) in &mut self.nodes {
            handle.events_generated += 1;
            
            let evt = Event::new(
                node_id.clone(),
                handle.events_generated,
                EventKind::Custom(ritma_lab_proto::CustomEvent {
                    event_type: event.event_type.clone(),
                    data: event.params.clone(),
                }),
            );
            
            self.evidence_collector.record_event(evt).await?;
        }

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping lab");

        {
            let mut state = self.state.write().await;
            state.status = LabStatus::Stopping;
        }

        // Stop traffic
        self.traffic_generator.stop_all();

        // Clear chaos
        self.chaos_controller.clear_all();

        // Seal final window before stopping
        self.evidence_collector.seal_window().await?;

        // Auto-export evidence to lab_dir/output before stopping
        let output_path = self.lab_dir.join("output");
        if let Err(e) = tokio::fs::create_dir_all(&output_path).await {
            info!("Failed to create output dir: {}", e);
        } else {
            let _ = self.evidence_collector.export(output_path.to_str().unwrap_or("./output")).await;
            info!(path = %output_path.display(), "Auto-exported evidence on stop");
        }

        // Stop evidence collector
        self.evidence_collector.stop().await?;

        // Clear nodes
        self.nodes.clear();

        {
            let mut state = self.state.write().await;
            state.status = LabStatus::Stopped;
        }

        info!("Lab stopped");
        Ok(())
    }

    pub async fn export(&self, output_path: &str) -> Result<String> {
        self.evidence_collector.export(output_path).await
    }

    pub async fn state(&self) -> LabState {
        self.state.read().await.clone()
    }

    pub async fn status(&self) -> String {
        let state = self.state.read().await;
        let stats = self.evidence_collector.stats().await;
        
        format!(
            "Status: {:?}\nRun ID: {}\nPhase: {}\nEvents: {}\nWindows: {}",
            state.status,
            state.run_id,
            state.current_phase.as_deref().unwrap_or("none"),
            stats.events_collected,
            stats.windows_sealed,
        )
    }
}

impl Default for LabOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}
