use serde::{Deserialize, Serialize};
use std::fs::read_to_string;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    TransitionLogs,
    DigFiles,
    PolicyCommit,
    MerkleProofs,
    MicroProofs,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSpec {
    /// Future-proof container for validation logic (e.g. small DSL or TruthScript snippet).
    pub script: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub control_id: String,
    pub framework: String,
    pub intent: String,
    #[serde(default)]
    pub requirements: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<EvidenceKind>,
    pub validation: ValidationSpec,
}

pub fn load_controls_from_file(path: &str) -> Result<Vec<Control>, String> {
    let content = read_to_string(path)
        .map_err(|e| format!("failed to read controls file {}: {}", path, e))?;

    serde_json::from_str::<Vec<Control>>(&content)
        .map_err(|e| format!("failed to parse controls from {}: {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn roundtrip_controls_json() {
        let controls = vec![Control {
            control_id: "AC-3".to_string(),
            framework: "SOC2".to_string(),
            intent: "Ensure access to customer data is restricted.".to_string(),
            requirements: vec![
                "All data access events must be logged.".to_string(),
                "Only whitelisted services may access sensitive data.".to_string(),
            ],
            evidence: vec![EvidenceKind::TransitionLogs, EvidenceKind::DigFiles],
            validation: ValidationSpec {
                script: "event.type == \"data_access\" -> event.actor in allowed_list".to_string(),
            },
        }];

        let json = serde_json::to_string(&controls).unwrap();
        let decoded: Vec<Control> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].control_id, "AC-3");
    }

    #[test]
    fn load_controls_from_file_works() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("controls.json");
        let mut f = std::fs::File::create(&path).unwrap();
        let data = r#"[
            {
                "control_id": "AC-3",
                "framework": "SOC2",
                "intent": "Ensure access to customer data is restricted.",
                "requirements": [
                    "All data access events must be logged.",
                    "Only whitelisted services may access sensitive data."
                ],
                "evidence": ["transition_logs", "dig_files"],
                "validation": {
                    "script": "event.type == \"data_access\" -> event.actor in allowed_list"
                }
            }
        ]"#;
        f.write_all(data.as_bytes()).unwrap();
        f.sync_all().unwrap();

        let loaded = load_controls_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].framework, "SOC2");
    }
}
