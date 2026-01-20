use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub scenario: ScenarioMetadata,
    pub phases: Vec<Phase>,
    #[serde(default)]
    pub chaos: Vec<ChaosAction>,
    #[serde(default)]
    pub assertions: Vec<Assertion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioMetadata {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub duration_seconds: u32,
    #[serde(default)]
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub name: String,
    pub start: u32,
    pub duration: u32,
    #[serde(default)]
    pub traffic: Option<TrafficSpec>,
    #[serde(default)]
    pub events: Vec<ScriptedEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSpec {
    #[serde(rename = "type")]
    pub traffic_type: String,
    #[serde(default)]
    pub rps: u32,
    #[serde(default)]
    pub distribution: String,
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub patterns: Vec<TrafficPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPattern {
    #[serde(default)]
    pub src: Option<String>,
    #[serde(default)]
    pub dst: Option<String>,
    #[serde(default)]
    pub rps: u32,
    #[serde(rename = "type", default)]
    pub pattern_type: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptedEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(flatten)]
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosAction {
    pub action: ChaosType,
    pub target: String,
    pub start: u32,
    #[serde(default)]
    pub duration: Option<u32>,
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChaosType {
    Latency,
    PacketLoss,
    Bandwidth,
    Down,
    Restart,
    CpuPressure,
    MemoryPressure,
    DiskSlow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    #[serde(rename = "type")]
    pub assertion_type: String,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub min: Option<u64>,
    #[serde(default)]
    pub max: Option<u64>,
    #[serde(default)]
    pub equals: Option<u64>,
    #[serde(default)]
    pub description: Option<String>,
}

impl Scenario {
    pub fn validate(&self) -> Result<(), String> {
        if self.phases.is_empty() {
            return Err("Scenario must have at least one phase".to_string());
        }

        let mut last_end = 0u32;
        for phase in &self.phases {
            if phase.start < last_end {
                return Err(format!(
                    "Phase {} starts at {} but previous phase ends at {}",
                    phase.name, phase.start, last_end
                ));
            }
            last_end = phase.start + phase.duration;
        }

        if last_end > self.scenario.duration_seconds {
            return Err(format!(
                "Phases extend to {} but scenario duration is {}",
                last_end, self.scenario.duration_seconds
            ));
        }

        Ok(())
    }

    pub fn get_phase_at(&self, seconds: u32) -> Option<&Phase> {
        self.phases
            .iter()
            .find(|p| seconds >= p.start && seconds < p.start + p.duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_parse() {
        let yaml = r#"
scenario:
  name: test-scenario
  duration_seconds: 60
  seed: 42
phases:
  - name: warmup
    start: 0
    duration: 20
    traffic:
      type: normal
      rps: 10
  - name: attack
    start: 20
    duration: 40
    traffic:
      type: burst
      rps: 100
chaos:
  - action: latency
    target: node-b
    start: 30
    duration: 10
    params:
      latency_ms: 200
"#;
        let scenario: Scenario = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(scenario.scenario.name, "test-scenario");
        assert_eq!(scenario.phases.len(), 2);
        assert_eq!(scenario.chaos.len(), 1);
        assert!(scenario.validate().is_ok());
    }
}
