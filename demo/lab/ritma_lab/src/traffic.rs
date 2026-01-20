use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use ritma_lab_proto::{
    Event, EventKind, HttpRequestEvent, HttpResponseEvent, CorrelationContext,
    InferenceRequestEvent, InferenceResponseEvent, GuardrailTriggerEvent,
};

pub struct TrafficGenerator {
    rng: StdRng,
    request_templates: Vec<RequestTemplate>,
    ai_mode: bool,
    model_id: String,
    model_version: String,
}

struct RequestTemplate {
    method: String,
    path: String,
    weight: u32,
}

impl TrafficGenerator {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            request_templates: vec![
                RequestTemplate { method: "GET".into(), path: "/api/health".into(), weight: 20 },
                RequestTemplate { method: "GET".into(), path: "/api/products".into(), weight: 30 },
                RequestTemplate { method: "GET".into(), path: "/api/products/{id}".into(), weight: 20 },
                RequestTemplate { method: "POST".into(), path: "/api/cart".into(), weight: 15 },
                RequestTemplate { method: "POST".into(), path: "/api/auth/login".into(), weight: 10 },
                RequestTemplate { method: "POST".into(), path: "/api/checkout".into(), weight: 5 },
            ],
            ai_mode: false,
            model_id: "loan-approval".into(),
            model_version: "v1".into(),
        }
    }

    pub fn set_ai_mode(&mut self, enabled: bool) {
        self.ai_mode = enabled;
    }

    pub fn set_model(&mut self, model_id: &str, version: &str) {
        self.model_id = model_id.to_string();
        self.model_version = version.to_string();
    }

    pub fn generate_event(&mut self, node_id: String, sequence: u64) -> Event {
        let request_id = format!("req_{}", uuid::Uuid::now_v7());
        let trace_id = format!("trace_{}", uuid::Uuid::now_v7());
        let user_id = format!("user_{}", self.rng.gen_range(1..100));
        let span_id = format!("span_{}", self.rng.gen::<u32>());
        let session_id = format!("sess_{}", self.rng.gen::<u32>());

        // Generate AI events if in AI mode
        let kind = if self.ai_mode {
            self.generate_ai_event()
        } else {
            self.generate_http_event(&node_id)
        };
        
        Event::new(node_id, sequence, kind).with_correlation(CorrelationContext {
            request_id: Some(request_id),
            trace_id: Some(trace_id),
            span_id: Some(span_id),
            user_id: Some(user_id),
            session_id: Some(session_id),
        })
    }

    fn generate_http_event(&mut self, node_id: &str) -> EventKind {
        let template_idx = self.pick_template_idx();
        let method = self.request_templates[template_idx].method.clone();
        let path_template = self.request_templates[template_idx].path.clone();
        let path = self.interpolate_path(&path_template);
        let status = self.generate_status();
        let latency_ms = self.generate_latency();

        if self.rng.gen_bool(0.5) {
            let content_length = if method == "POST" { Some(self.rng.gen_range(100..1000)) } else { None };
            let headers_hash = format!("{:x}", self.rng.gen::<u64>());
            EventKind::HttpRequest(HttpRequestEvent {
                method,
                path,
                host: format!("{}.lab.local", node_id),
                user_agent: Some("RitmaLab/1.0".to_string()),
                content_length,
                headers_hash,
            })
        } else {
            EventKind::HttpResponse(HttpResponseEvent {
                status,
                content_length: Some(self.rng.gen_range(100..10000)),
                latency_ms,
            })
        }
    }

    fn generate_ai_event(&mut self) -> EventKind {
        let event_type = self.rng.gen_range(0..100);
        
        match event_type {
            0..=39 => {
                // 40% - Inference Request
                EventKind::InferenceRequest(InferenceRequestEvent {
                    model_id: self.model_id.clone(),
                    model_version: self.model_version.clone(),
                    input_hash: format!("{:x}", self.rng.gen::<u64>()),
                    input_token_count: Some(self.rng.gen_range(50..500)),
                })
            }
            40..=79 => {
                // 40% - Inference Response
                let decisions = ["approve", "reject", "escalate", "review"];
                let decision = decisions[self.rng.gen_range(0..decisions.len())];
                EventKind::InferenceResponse(InferenceResponseEvent {
                    output_hash: format!("{:x}", self.rng.gen::<u64>()),
                    output_token_count: Some(self.rng.gen_range(10..200)),
                    latency_ms: self.rng.gen_range(50..500),
                    confidence_score: Some(self.rng.gen_range(0.6..0.99) as f32),
                    decision_type: Some(decision.to_string()),
                })
            }
            80..=94 => {
                // 15% - Guardrail Trigger
                let guardrail_types = ["pii_detection", "jailbreak_attempt", "toxicity", "prompt_injection", "data_leak"];
                let actions = ["blocked", "flagged", "logged", "escalated"];
                EventKind::GuardrailTrigger(GuardrailTriggerEvent {
                    guardrail_id: format!("gr_{}", self.rng.gen::<u32>()),
                    guardrail_type: guardrail_types[self.rng.gen_range(0..guardrail_types.len())].to_string(),
                    action_taken: actions[self.rng.gen_range(0..actions.len())].to_string(),
                    reason: Some(format!("Detected potential {} violation", guardrail_types[self.rng.gen_range(0..guardrail_types.len())])),
                })
            }
            _ => {
                // 5% - HTTP (model API call)
                EventKind::HttpRequest(HttpRequestEvent {
                    method: "POST".to_string(),
                    path: format!("/v1/models/{}/predict", self.model_id),
                    host: "ml-gateway.lab.local".to_string(),
                    user_agent: Some("MLClient/2.0".to_string()),
                    content_length: Some(self.rng.gen_range(500..5000)),
                    headers_hash: format!("{:x}", self.rng.gen::<u64>()),
                })
            }
        }
    }

    fn pick_template_idx(&mut self) -> usize {
        let total_weight: u32 = self.request_templates.iter().map(|t| t.weight).sum();
        let mut pick = self.rng.gen_range(0..total_weight);
        
        for (i, template) in self.request_templates.iter().enumerate() {
            if pick < template.weight {
                return i;
            }
            pick -= template.weight;
        }
        
        0
    }

    fn interpolate_path(&mut self, path: &str) -> String {
        if path.contains("{id}") {
            path.replace("{id}", &self.rng.gen_range(1..1000).to_string())
        } else {
            path.to_string()
        }
    }

    fn generate_status(&mut self) -> u16 {
        let roll = self.rng.gen_range(0..100);
        match roll {
            0..=85 => 200,
            86..=90 => 201,
            91..=93 => 400,
            94..=96 => 401,
            97..=98 => 404,
            _ => 500,
        }
    }

    fn generate_latency(&mut self) -> u32 {
        // Most requests are fast, some are slow
        let roll = self.rng.gen_range(0..100);
        match roll {
            0..=70 => self.rng.gen_range(5..50),
            71..=90 => self.rng.gen_range(50..200),
            91..=98 => self.rng.gen_range(200..1000),
            _ => self.rng.gen_range(1000..5000),
        }
    }

    pub fn stop_all(&mut self) {
        // Reset RNG for reproducibility on next run
    }
}
