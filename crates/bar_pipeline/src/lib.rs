use bar_powers::{PipelinePower, PipelineInput, PipelineOutput, BarPowerError};
use common_models::{DecisionEvent, Verdict, VerdictType, Severity, VerdictExplain, VerdictRangesUsed, Actor, ActorType, Subject, Action, Context, EnvStamp, RedactionInfo};
use index_db::IndexDb;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("power error: {0}")]
    Power(#[from] BarPowerError),
    #[error("index_db error: {0}")]
    IndexDb(#[from] index_db::IndexDbError),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PipelineError>;

/// Minimal BAR pipeline that converts adapter output into canonical DecisionEvent
/// and persists events/verdicts via IndexDB.
pub struct MinimalPipeline {
    index_db: IndexDb,
}

impl MinimalPipeline {
    pub fn new(index_db: IndexDb) -> Self {
        Self { index_db }
    }

    /// Process a raw event candidate into a canonical DecisionEvent and persist it.
    pub fn process_event(&self, input: PipelineInput) -> Result<DecisionEvent> {
        // Convert candidate to canonical DecisionEvent
        let event = DecisionEvent {
            event_id: format!("evt_{}", uuid::Uuid::new_v4()),
            namespace_id: input.candidate.namespace_id.clone(),
            ts: chrono::Utc::now().to_rfc3339(),
            event_type: input.candidate.event_type.clone(),
            actor: Actor {
                r#type: ActorType::Service,
                id_hash: "unknown".to_string(),
                roles: vec![],
            },
            subject: Subject {
                r#type: "resource".to_string(),
                id_hash: "unknown".to_string(),
            },
            action: Action {
                name: "observe".to_string(),
                params_hash: None,
            },
            context: Context {
                request_id: None,
                trace_id: None,
                ip_hash: None,
                user_agent_hash: None,
            },
            env_stamp: EnvStamp {
                env: "unknown".to_string(),
                service: "bar".to_string(),
                build_hash: "dev".to_string(),
                region: "local".to_string(),
                trust_flags: vec![],
            },
            redaction: RedactionInfo {
                applied: vec![],
                strategy: None,
            },
            stage_trace: vec![],
        };

        // Persist to IndexDB
        self.index_db.insert_event_from_decision(&event)?;

        Ok(event)
    }

    /// Create a simple verdict for an event and persist it.
    pub fn create_verdict(&self, event: &DecisionEvent, verdict_type: VerdictType) -> Result<Verdict> {
        let verdict = Verdict {
            verdict_id: format!("v_{}", uuid::Uuid::new_v4()),
            namespace_id: event.namespace_id.clone(),
            event_id: event.event_id.clone(),
            verdict_type,
            severity: Severity::Low,
            confidence: 0.5,
            reason_codes: vec![],
            explain: VerdictExplain {
                summary: Some("Minimal pipeline verdict".to_string()),
                evidence_refs: vec![],
            },
            ranges_used: VerdictRangesUsed {
                json: serde_json::json!({}),
            },
            contract_hash: None,
            policy_pack: None,
        };

        // Persist to IndexDB
        self.index_db.insert_verdict_from_model(&verdict)?;

        Ok(verdict)
    }
}

impl PipelinePower for MinimalPipeline {
    fn process(&self, input: PipelineInput) -> bar_powers::Result<PipelineOutput> {
        let event = self.process_event(input)
            .map_err(|e| BarPowerError::Pipeline(e.to_string()))?;
        
        let verdict = self.create_verdict(&event, VerdictType::Other)
            .map_err(|e| BarPowerError::Pipeline(e.to_string()))?;

        Ok(PipelineOutput {
            decision_event: Some(serde_json::to_value(&event).unwrap()),
            verdict: Some(serde_json::to_value(&verdict).unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bar_powers::DecisionEventCandidate;
    use tempfile::TempDir;

    #[test]
    fn minimal_pipeline_processes_event() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let db = IndexDb::open(path.to_str().unwrap()).expect("open index_db");
        
        let pipeline = MinimalPipeline::new(db);
        
        let input = PipelineInput {
            candidate: DecisionEventCandidate {
                namespace_id: "ns://test/prod/app/svc".to_string(),
                event_type: "TEST".to_string(),
                raw: serde_json::json!({}),
            },
        };

        let output = pipeline.process(input).expect("process");
        assert!(output.decision_event.is_some());
        assert!(output.verdict.is_some());
    }
}
