use anyhow::Result;
use ritma_lab_proto::Scenario;

pub struct ScenarioEngine {
    scenario: Scenario,
    current_phase_idx: usize,
    start_time: Option<std::time::Instant>,
}

impl ScenarioEngine {
    pub fn new(scenario: Scenario) -> Result<Self> {
        scenario.validate().map_err(|e| anyhow::anyhow!(e))?;
        Ok(Self {
            scenario,
            current_phase_idx: 0,
            start_time: None,
        })
    }

    pub fn start(&mut self) {
        self.start_time = Some(std::time::Instant::now());
        self.current_phase_idx = 0;
    }

    pub fn elapsed_seconds(&self) -> u32 {
        self.start_time
            .map(|t| t.elapsed().as_secs() as u32)
            .unwrap_or(0)
    }

    pub fn is_complete(&self) -> bool {
        self.elapsed_seconds() >= self.scenario.scenario.duration_seconds
    }

    pub fn current_phase(&self) -> Option<&ritma_lab_proto::Phase> {
        let elapsed = self.elapsed_seconds();
        self.scenario.get_phase_at(elapsed)
    }

    pub fn scenario(&self) -> &Scenario {
        &self.scenario
    }

    pub fn duration_seconds(&self) -> u32 {
        self.scenario.scenario.duration_seconds
    }
}
