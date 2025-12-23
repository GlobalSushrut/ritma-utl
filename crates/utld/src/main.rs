#![allow(clippy::uninlined_format_args)]

#[cfg(all(target_os = "linux", feature = "tls"))]
mod tls_listener;

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use biz_api::{BusinessPlugin, MetricKind, ProductId, UsageEvent};
use core_types::{Hash, UID};
use dig_index::DigIndexEntry;
use forensics_store::persist_dig_to_fs;
use policy_engine::{EngineAction, EngineEvent, PolicyEngine};
use reqwest::blocking::Client as HttpClient;
use security_events::{append_decision_event, DecisionEvent};
use security_os::MtlsConfig;
use serde::Deserialize;
use serde_json::Value as EngineValue;
use sot_root::StateOfTruthRoot;
use truthscript::{Action as PolicyAction, Policy};
use utld::{handle_request, NodeRequest, NodeResponse, UtlNode};
use zk_snark::{self, Fr as SnarkFr};

#[cfg(feature = "bar_governance")]
use bar_client::{BarClient, BarClientError};
#[cfg(feature = "bar_governance")]
use bar_core::{ObservedEvent as BarObservedEvent, VerdictDecision as BarVerdictDecision};

struct FileBusinessPlugin {
    path: String,
}

impl FileBusinessPlugin {
    fn new(path: String) -> Self {
        Self { path }
    }
}

#[cfg(feature = "bar_governance")]
struct BarGovernance {
    client: Option<BarClient>,
    mode: BarGovernanceMode,
}

#[cfg(feature = "bar_governance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BarGovernanceMode {
    Off,
    Observe,
    Enforce,
}

#[cfg(feature = "bar_governance")]
impl BarGovernanceMode {
    fn from_env() -> Self {
        match std::env::var("UTLD_BAR_GOVERNANCE_MODE")
            .unwrap_or_else(|_| "off".to_string())
            .to_lowercase()
            .as_str()
        {
            "observe" | "observe-only" => BarGovernanceMode::Observe,
            "enforce" => BarGovernanceMode::Enforce,
            _ => BarGovernanceMode::Off,
        }
    }
}

#[cfg(feature = "bar_governance")]
impl Default for BarGovernance {
    fn default() -> Self {
        let mode = BarGovernanceMode::from_env();
        let client = match mode {
            BarGovernanceMode::Off => None,
            _ => Some(BarClient::from_env()),
        };
        BarGovernance { client, mode }
    }
}

#[cfg(feature = "bar_governance")]
impl GovernanceEngine for BarGovernance {
    fn maybe_apply(
        &mut self,
        req: &mut NodeRequest,
        _node: &mut UtlNode,
        _plugin: &Option<Arc<dyn BusinessPlugin + Send + Sync>>,
    ) -> Option<NodeResponse> {
        // Default behavior: BAR governance is completely disabled unless
        // both the feature is enabled at compile time and the runtime mode
        // is set via UTLD_BAR_GOVERNANCE_MODE.
        if self.mode == BarGovernanceMode::Off {
            let _ = node_request_to_bar_event(req);
            return None;
        }

        let client = match &self.client {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "bar_governance enabled but BarClient is not initialized; deferring to local handler"
                );
                let _ = node_request_to_bar_event(req);
                return None;
            }
        };

        let event = match node_request_to_bar_event(req) {
            Some(ev) => ev,
            None => {
                // Not a transition we currently project into BAR; fall back.
                return None;
            }
        };

        let verdict = match client.evaluate(&event) {
            Ok(v) => v,
            Err(e) => {
                match e {
                    BarClientError::DaemonError(msg) => {
                        tracing::warn!("BAR daemon returned error: {}", msg);
                    }
                    _ => {
                        tracing::warn!("BAR client error: {}", e);
                    }
                }
                // On any error, we fail open to avoid breaking UTL.
                return None;
            }
        };

        match self.mode {
            BarGovernanceMode::Observe => {
                // Observe-only: we log the verdict but do not alter behavior.
                tracing::warn!(
                    "BAR observe-only verdict: decision={:?} reason={:?} obligations={:?}",
                    verdict.decision,
                    verdict.reason,
                    verdict.obligations,
                );
                None
            }
            BarGovernanceMode::Enforce => {
                match verdict.decision {
                    BarVerdictDecision::Allow => None,
                    BarVerdictDecision::ObserveOnly => {
                        // In enforce mode, an observe-only verdict behaves
                        // like allow but we log it explicitly so operators
                        // can see BAR choosing to observe instead of deny.
                        tracing::warn!(
                            "BAR enforce-mode observe_only verdict: reason={:?} rule_ids={:?} obligations={:?}",
                            verdict.reason,
                            verdict.rule_ids,
                            verdict.obligations,
                        );
                        None
                    }
                    BarVerdictDecision::Deny => {
                        // TODO: refine mapping into richer NodeResponse once we
                        // have a dedicated error type for governance denials.
                        Some(NodeResponse::Error {
                            message: format!(
                                "request denied by BAR governance: {}",
                                verdict.reason.unwrap_or_else(|| "no_reason".to_string())
                            ),
                        })
                    }
                }
            }
            BarGovernanceMode::Off => None,
        }
    }
}

/// Convert a NodeRequest::RecordTransition into a BAR ObservedEvent. This is
/// compiled only when `bar_governance` is enabled and is currently unused at
/// runtime; it prepares the seam for BAR-backed governance.
#[cfg(feature = "bar_governance")]
fn node_request_to_bar_event(req: &NodeRequest) -> Option<BarObservedEvent> {
    match req {
        NodeRequest::RecordTransition {
            entity_id,
            root_id,
            p_container,
            logic_ref,
            ..
        } => {
            let mut properties = BTreeMap::new();

            // Copy all params as JSON strings for now.
            for (k, v) in p_container.iter() {
                properties.insert(k.clone(), serde_json::Value::String(v.clone()));
            }

            // Ensure some core fields are always present.
            properties
                .entry("root_id".to_string())
                .or_insert_with(|| serde_json::Value::String(root_id.to_string()));
            properties
                .entry("logic_ref".to_string())
                .or_insert_with(|| serde_json::Value::String(logic_ref.clone()));

            let namespace_id = p_container
                .get("namespace_id")
                .cloned()
                .unwrap_or_else(|| "default".to_string());

            let kind = p_container
                .get("event_kind")
                .cloned()
                .unwrap_or_else(|| "record_transition".to_string());

            Some(BarObservedEvent {
                namespace_id,
                kind,
                entity_id: Some(UID(*entity_id)),
                properties,
            })
        }
        _ => None,
    }
}

fn load_mtls_config_from_env() -> Option<MtlsConfig> {
    let ca_bundle_path = std::env::var("UTLD_MTLS_CA").ok()?;
    let cert_path = std::env::var("UTLD_MTLS_CERT").ok()?;
    let key_path = std::env::var("UTLD_MTLS_KEY").ok()?;

    let require_client_auth = std::env::var("UTLD_MTLS_REQUIRE_CLIENT_AUTH")
        .ok()
        .map(|v| {
            let v = v.to_lowercase();
            !(v == "0" || v == "false" || v == "no")
        })
        .unwrap_or(true);

    Some(MtlsConfig {
        ca_bundle_path,
        cert_path,
        key_path,
        require_client_auth,
    })
}

impl BusinessPlugin for FileBusinessPlugin {
    fn on_usage_event(&self, event: &UsageEvent) {
        let line = match serde_json::to_string(event) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to serialize usage event: {}", e);
                return;
            }
        };

        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{}", line) {
                    eprintln!("failed to append usage event to {}: {}", self.path, e);
                }
            }
            Err(e) => {
                eprintln!("failed to open usage events file {}: {}", self.path, e);
            }
        }
    }
}

struct StdoutBusinessPlugin;

impl BusinessPlugin for StdoutBusinessPlugin {
    fn on_usage_event(&self, event: &UsageEvent) {
        match serde_json::to_string(event) {
            Ok(line) => println!("{}", line),
            Err(e) => eprintln!("failed to serialize usage event for stdout: {}", e),
        }
    }
}

struct HttpBusinessPlugin {
    client: HttpClient,
    url: String,
}

impl HttpBusinessPlugin {
    fn new(url: String) -> Result<Self, String> {
        let client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .map_err(|e| format!("failed to build http client: {}", e))?;
        Ok(Self { client, url })
    }
}

impl BusinessPlugin for HttpBusinessPlugin {
    fn on_usage_event(&self, event: &UsageEvent) {
        match self.client.post(&self.url).json(event).send() {
            Ok(resp) => {
                if !resp.status().is_success() {
                    eprintln!(
                        "usage http sink got non-success status {} from {}",
                        resp.status(),
                        self.url
                    );
                }
            }
            Err(e) => {
                eprintln!("failed to POST usage event to {}: {}", self.url, e);
            }
        }
    }
}

struct CompositeBusinessPlugin {
    sinks: Vec<Arc<dyn BusinessPlugin + Send + Sync>>,
}

impl CompositeBusinessPlugin {
    fn new(sinks: Vec<Arc<dyn BusinessPlugin + Send + Sync>>) -> Self {
        Self { sinks }
    }
}

impl BusinessPlugin for CompositeBusinessPlugin {
    fn on_usage_event(&self, event: &UsageEvent) {
        for sink in &self.sinks {
            sink.on_usage_event(event);
        }
    }
}

fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();
    let socket_path = std::env::var("UTLD_SOCKET").unwrap_or_else(|_| "/tmp/utld.sock".into());

    if let Some(cfg) = load_mtls_config_from_env() {
        tracing::info!(
            "mtls config loaded: ca_bundle_path={}, cert_path={}, key_path={}, require_client_auth={}",
            cfg.ca_bundle_path,
            cfg.cert_path,
            cfg.key_path,
            cfg.require_client_auth,
        );
    }

    if Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    if let Ok(meta) = std::fs::metadata(&socket_path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o660);
        if let Err(e) = std::fs::set_permissions(&socket_path, perms) {
            eprintln!("failed to set permissions on {}: {}", socket_path, e);
        }
    }

    tracing::info!("utld listening on {}", socket_path);

    let mut node = UtlNode::new();

    if let Err(e) = load_roots_into_node(&mut node) {
        eprintln!("failed to load persisted roots: {}", e);
    }

    let node = Arc::new(Mutex::new(node));

    let engine = load_policy_from_env()
        .map(PolicyEngine::new)
        .map(|e| Arc::new(Mutex::new(e)));

    // Optional business plugins for usage metering / billing.
    // - UTLD_USAGE_EVENTS=/path/usage.jsonl  -> append JSONL lines to that file
    // - UTLD_USAGE_STDOUT=1                 -> print UsageEvent JSON lines to stdout
    // - UTLD_USAGE_HTTP_URL=http://host:port/ingest-usage -> POST UsageEvent JSON to billing_daemon
    let mut sinks: Vec<Arc<dyn BusinessPlugin + Send + Sync>> = Vec::new();

    if let Ok(path) = std::env::var("UTLD_USAGE_EVENTS") {
        if !path.trim().is_empty() {
            sinks.push(Arc::new(FileBusinessPlugin::new(path)));
        }
    }

    if let Ok(val) = std::env::var("UTLD_USAGE_STDOUT") {
        if !val.trim().is_empty() && val != "0" {
            sinks.push(Arc::new(StdoutBusinessPlugin));
        }
    }

    if let Ok(url) = std::env::var("UTLD_USAGE_HTTP_URL") {
        if !url.trim().is_empty() {
            match HttpBusinessPlugin::new(url) {
                Ok(p) => sinks.push(Arc::new(p)),
                Err(e) => eprintln!("failed to init HttpBusinessPlugin: {}", e),
            }
        }
    }

    let plugin: Option<Arc<dyn BusinessPlugin + Send + Sync>> = if sinks.is_empty() {
        None
    } else {
        Some(Arc::new(CompositeBusinessPlugin::new(sinks)))
    };

    // Optional TCP+TLS listener.
    #[cfg(all(target_os = "linux", feature = "tls"))]
    if let Ok(tls_addr_str) = std::env::var("UTLD_TLS_ADDR") {
        if let Some(cfg) = load_mtls_config_from_env() {
            if let Ok(tls_addr) = tls_addr_str.parse() {
                let node_tls = Arc::clone(&node);
                let engine_tls = engine.as_ref().map(Arc::clone);
                let plugin_tls = plugin.as_ref().map(Arc::clone);
                thread::spawn(move || {
                    if let Err(e) = tls_listener::start_tls_listener(
                        tls_addr, cfg, node_tls, engine_tls, plugin_tls,
                    ) {
                        tracing::error!("TLS listener error: {}", e);
                    }
                });
            } else {
                tracing::error!("invalid UTLD_TLS_ADDR: {}", tls_addr_str);
            }
        }
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let node_clone = Arc::clone(&node);
                let engine_clone = engine.as_ref().map(Arc::clone);
                let plugin_clone = plugin.as_ref().map(Arc::clone);
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, node_clone, engine_clone, plugin_clone) {
                        eprintln!("client error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }

    Ok(())
}

fn load_policy_from_env() -> Option<Policy> {
    let path = match std::env::var("UTLD_POLICY") {
        Ok(p) => p,
        Err(_) => return None,
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to read policy file {}: {}", path, e);
            return None;
        }
    };

    match Policy::from_json_str(&content) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("failed to parse policy from {}: {}", path, e);
            None
        }
    }
}

fn state_file_path() -> String {
    std::env::var("UTLD_STATE_FILE").unwrap_or_else(|_| "./utld_roots.json".to_string())
}

fn load_roots_into_node(node: &mut UtlNode) -> std::io::Result<()> {
    use std::io::ErrorKind;

    let path = state_file_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };

    #[derive(Deserialize)]
    struct PersistedState {
        roots: Vec<StateOfTruthRoot>,
    }

    let persisted: PersistedState = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to parse persisted roots {}: {}", path, e);
            return Ok(());
        }
    };

    for root in persisted.roots {
        node.register_root(root);
    }

    Ok(())
}

trait GovernanceEngine {
    fn maybe_apply(
        &mut self,
        req: &mut NodeRequest,
        node: &mut UtlNode,
        plugin: &Option<Arc<dyn BusinessPlugin + Send + Sync>>,
    ) -> Option<NodeResponse>;
}

struct PolicyGovernance<'a> {
    engine: &'a mut PolicyEngine,
}

impl<'a> GovernanceEngine for PolicyGovernance<'a> {
    fn maybe_apply(
        &mut self,
        req: &mut NodeRequest,
        node: &mut UtlNode,
        plugin: &Option<Arc<dyn BusinessPlugin + Send + Sync>>,
    ) -> Option<NodeResponse> {
        enforce_policy(self.engine, req, node, plugin)
    }
}

fn enforce_policy(
    engine: &mut PolicyEngine,
    req: &mut NodeRequest,
    node: &mut UtlNode,
    plugin: &Option<Arc<dyn BusinessPlugin + Send + Sync>>,
) -> Option<NodeResponse> {
    match req {
        NodeRequest::RecordTransition {
            entity_id,
            root_id,
            p_container,
            logic_ref,
            ..
        } => {
            let mut fields: BTreeMap<String, EngineValue> = BTreeMap::new();
            fields.insert(
                "entity_id".to_string(),
                EngineValue::String(entity_id.to_string()),
            );
            fields.insert(
                "root_id".to_string(),
                EngineValue::String(root_id.to_string()),
            );
            fields.insert(
                "logic_ref".to_string(),
                EngineValue::String(logic_ref.clone()),
            );

            for (k, v) in p_container.iter() {
                if let Ok(n) = v.parse::<f64>() {
                    fields.insert(k.clone(), EngineValue::from(n));
                } else {
                    fields.insert(k.clone(), EngineValue::String(v.clone()));
                }
            }

            let kind = p_container
                .get("event_kind")
                .cloned()
                .unwrap_or_else(|| "record_transition".to_string());

            let event = EngineEvent {
                kind: kind.clone(),
                fields,
            };
            let actions = engine.evaluate(&event);

            // Inject policy decision metadata into params so it is visible in digs.
            if !actions.is_empty() {
                let (policy_name, policy_version) = engine.policy_meta();

                let mut decision = "allow_with_actions".to_string();
                let mut rule_names: Vec<String> = Vec::new();
                let mut action_kinds: Vec<String> = Vec::new();

                for EngineAction { rule_name, action } in &actions {
                    rule_names.push(rule_name.clone());
                    let kind_str = match action {
                        PolicyAction::Deny { .. } => {
                            decision = "deny".to_string();
                            "deny"
                        }
                        PolicyAction::SealCurrentDig => "seal_current_dig",
                        PolicyAction::FlagForInvestigation { .. } => "flag_for_investigation",
                        PolicyAction::RequireDistilliumProof => "require_distillium_proof",
                        PolicyAction::RequireUnknownLogicCapsule => "require_unknown_logic_capsule",
                        PolicyAction::CaptureInput => "capture_input",
                        PolicyAction::CaptureOutput => "capture_output",
                        PolicyAction::RecordField { .. } => "record_field",
                        PolicyAction::RequireSnarkProof => "require_snark_proof",
                        PolicyAction::RequirePolicyEvalProof => "require_policy_eval_proof",
                        PolicyAction::RequireDigInclusionProof => "require_dig_inclusion_proof",
                    };
                    action_kinds.push(kind_str.to_string());
                }

                // If there is a HIGH_THREAT + RequireSnarkProof action, run the
                // combined high-threat+Merkle SNARK once and capture its status
                // for logging in the structured DecisionEvent.
                let mut snark_status: Option<String> = None;
                for EngineAction { rule_name, action } in &actions {
                    if rule_name == "HIGH_THREAT" {
                        match action {
                            PolicyAction::RequireSnarkProof
                            | PolicyAction::RequirePolicyEvalProof
                            | PolicyAction::RequireDigInclusionProof => {
                                snark_status =
                                    run_high_threat_merkle_snark(node, UID(*root_id), rule_name);
                                break;
                            }
                            _ => {}
                        }
                    }
                }

                // Emit a structured decision event for external consumers.
                let tenant_id = p_container.get("tenant_id").cloned();
                let src_did = p_container.get("src_did").cloned();
                let dst_did = p_container.get("dst_did").cloned();
                let actor_did = p_container.get("actor_did").cloned();
                let src_zone = p_container.get("src_zone").cloned();
                let dst_zone = p_container.get("dst_zone").cloned();

                let policy_commit_id = std::env::var("UTLD_POLICY_COMMIT_ID").ok();

                let event_rec = DecisionEvent {
                    ts: 0,
                    tenant_id,
                    root_id: root_id.to_string(),
                    entity_id: entity_id.to_string(),
                    event_kind: kind.clone(),
                    policy_name: Some(policy_name.to_string()),
                    policy_version: Some(policy_version.to_string()),
                    policy_commit_id,
                    policy_decision: decision.clone(),
                    policy_rules: rule_names.clone(),
                    policy_actions: action_kinds.clone(),
                    src_did,
                    dst_did,
                    actor_did,
                    src_zone,
                    dst_zone,
                    snark_high_threat_merkle_status: snark_status,
                    schema_version: 0,
                    prev_hash: None,
                    record_hash: None,
                    consensus_decision: None,
                    consensus_threshold_met: None,
                    consensus_quorum_reached: None,
                    consensus_total_weight: None,
                    consensus_hash: None,
                    consensus_validator_count: None,
                    svc_policy_id: None,
                    svc_infra_id: None,
                };

                if let Err(e) = append_decision_event(&event_rec) {
                    eprintln!("failed to append decision event: {}", e);
                }

                // Emit truth snapshot for certain critical events
                if action_kinds.contains(&"seal_current_dig".to_string())
                    || action_kinds.contains(&"flag_for_investigation".to_string())
                    || event_rec.policy_decision == "deny"
                {
                    emit_truth_snapshot(event_rec.tenant_id.clone(), "policy_decision");
                }

                // Optional business usage hook: emit one decision usage event per
                // DecisionEvent when a tenant_id is present. This is a pure side
                // channel for metering/analytics and does not affect policy
                // behavior.
                if let Some(plugin_arc) = plugin.as_ref() {
                    if let Some(tid) = event_rec.tenant_id.clone() {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        let usage = UsageEvent {
                            ts: now,
                            tenant_id: tid,
                            product: ProductId::ManagedUtldClusters,
                            metric: MetricKind::Decisions,
                            quantity: 1,
                            root_id: Some(UID(*root_id)),
                            entity_id: None,
                            note: Some("decision_event".to_string()),
                        };

                        plugin_arc.on_usage_event(&usage);
                    }
                }

                p_container
                    .entry("policy_name".to_string())
                    .or_insert_with(|| policy_name.to_string());
                p_container
                    .entry("policy_version".to_string())
                    .or_insert_with(|| policy_version.to_string());
                p_container
                    .entry("policy_decision".to_string())
                    .or_insert(decision);

                if !rule_names.is_empty() {
                    let joined = rule_names.join(",");
                    p_container
                        .entry("policy_rules".to_string())
                        .or_insert(joined);
                }

                if !action_kinds.is_empty() {
                    let joined = action_kinds.join(",");
                    p_container
                        .entry("policy_actions".to_string())
                        .or_insert(joined);
                }
            }

            apply_engine_actions(actions, node, *root_id, plugin)
        }
        _ => None,
    }
}

fn apply_engine_actions(
    actions: Vec<EngineAction>,
    node: &mut UtlNode,
    root_id_raw: u128,
    plugin: &Option<Arc<dyn BusinessPlugin + Send + Sync>>,
) -> Option<NodeResponse> {
    let root_id = UID(root_id_raw);

    for EngineAction { rule_name, action } in &actions {
        match action {
            PolicyAction::Deny { reason } => {
                seal_and_index_current_dig(node, root_id, plugin);
                let msg = format!("denied_by_policy({}): {}", rule_name, reason);
                return Some(NodeResponse::Error { message: msg });
            }
            PolicyAction::SealCurrentDig => {
                seal_and_index_current_dig(node, root_id, plugin);
            }
            PolicyAction::RequireSnarkProof
            | PolicyAction::RequirePolicyEvalProof
            | PolicyAction::RequireDigInclusionProof => {
                if rule_name != "HIGH_THREAT" {
                    let circuit_id = UID::new();
                    match zk_snark::setup_equality(circuit_id) {
                        Ok(keys) => {
                            let x = SnarkFr::from(root_id.0 as u64);
                            match zk_snark::prove_equality(&keys, x)
                                .and_then(|proof| zk_snark::verify_equality(&keys, &proof, x))
                            {
                                Ok(true) => {
                                    eprintln!("snark_proof_ok (rule={})", rule_name);
                                }
                                Ok(false) => {
                                    eprintln!("snark_proof_invalid (rule={})", rule_name);
                                }
                                Err(e) => {
                                    eprintln!("snark_proof_error (rule={}): {:?}", rule_name, e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("snark_setup_error (rule={}): {:?}", rule_name, e);
                        }
                    }
                }
            }
            PolicyAction::FlagForInvestigation { .. }
            | PolicyAction::RequireDistilliumProof
            | PolicyAction::RequireUnknownLogicCapsule
            | PolicyAction::CaptureInput
            | PolicyAction::CaptureOutput
            | PolicyAction::RecordField { .. } => {
                if let PolicyAction::RequireDistilliumProof = action {
                    match node.generate_micro_proof_for_root(root_id) {
                        Ok(_) => {
                            eprintln!("distillium micro-proof generated (rule={})", rule_name);
                        }
                        Err(e) => {
                            eprintln!(
                                "failed to generate micro-proof for root {:?}: {:?}",
                                root_id, e
                            );
                        }
                    }
                } else {
                    eprintln!("policy_action fired (rule={}): {:?}", rule_name, action);
                }
            }
        }
    }

    None
}

fn latest_threat_score_scaled(node: &UtlNode, root_id: UID) -> Option<u16> {
    let records = node.records_for_root(root_id)?;
    let last = records.last()?;

    let score_str = last.p_container.0.get("threat_score")?;
    let score_f: f64 = score_str.parse().ok()?;
    let scaled = (score_f * 1000.0).round();
    if scaled < 0.0 || scaled > u16::MAX as f64 {
        return None;
    }

    Some(scaled as u16)
}

fn run_high_threat_merkle_snark(node: &UtlNode, root_id: UID, rule_name: &str) -> Option<String> {
    if let Some(score_scaled) = latest_threat_score_scaled(node, root_id) {
        // Build SNARK-friendly Merkle path for the latest record.
        if let Some(records) = node.records_for_root(root_id) {
            if !records.is_empty() {
                let last_index = records.len() - 1;
                let leaves: Vec<Hash> = records.iter().map(|r| r.leaf_hash()).collect();

                if let Some((root_fr, leaf_fr, siblings, dirs)) =
                    zk_snark::build_snark_merkle_path_from_hashes(&leaves, last_index)
                {
                    let circuit_id = UID::new();
                    match zk_snark::setup_high_threat_merkle(circuit_id, siblings.len()) {
                        Ok(keys) => {
                            match zk_snark::prove_high_threat_merkle(
                                &keys,
                                score_scaled,
                                leaf_fr,
                                &siblings,
                                &dirs,
                            )
                            .and_then(|(proof, root_again)| {
                                if root_again != root_fr {
                                    return Ok(false);
                                }
                                zk_snark::verify_high_threat_merkle(
                                    &keys,
                                    &proof,
                                    score_scaled,
                                    root_fr,
                                    leaf_fr,
                                )
                            }) {
                                Ok(true) => {
                                    eprintln!(
                                        "snark_high_threat_merkle_ok (rule={} score={} index={})",
                                        rule_name, score_scaled, last_index,
                                    );
                                    return Some("ok".to_string());
                                }
                                Ok(false) => {
                                    eprintln!(
                                        "snark_high_threat_merkle_invalid (rule={} score={} index={})",
                                        rule_name,
                                        score_scaled,
                                        last_index,
                                    );
                                    return Some("invalid".to_string());
                                }
                                Err(e) => {
                                    eprintln!(
                                        "snark_high_threat_merkle_error (rule={} score={} index={}): {:?}",
                                        rule_name,
                                        score_scaled,
                                        last_index,
                                        e,
                                    );
                                    return Some("error".to_string());
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "snark_high_threat_merkle_setup_error (rule={}): {:?}",
                                rule_name, e,
                            );
                        }
                    }
                } else {
                    eprintln!(
                        "snark_high_threat_merkle_path_error (rule={} root_id={} index={})",
                        rule_name, root_id.0, last_index,
                    );
                }
            } else {
                eprintln!(
                    "snark_high_threat_merkle_no_records (rule={} root_id={})",
                    rule_name, root_id.0
                );
            }
        } else {
            eprintln!(
                "snark_high_threat_merkle_missing_records (rule={} root_id={})",
                rule_name, root_id.0
            );
        }
    } else {
        eprintln!(
            "snark_high_threat_missing_score (rule={} root_id={})",
            rule_name, root_id.0
        );
    }

    None
}

fn seal_and_index_current_dig(
    node: &mut UtlNode,
    root_id: UID,
    plugin: &Option<Arc<dyn BusinessPlugin + Send + Sync>>,
) {
    let file_id = UID::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_range = (now, now);

    match node.seal_dig_for_root(root_id, file_id, time_range) {
        Ok(dig) => {
            if let Err(e) = persist_dig_file(root_id, &dig) {
                eprintln!("failed to persist dig file: {}", e);
                return;
            }

            // Append a minimal index entry so an external service can index digs.
            let mut tenant_id = None;
            let mut policy_name = None;
            let mut policy_version = None;
            let mut policy_decision = None;
            let mut storage_path = None;

            if let Some(first_rec) = dig.dig_records.first() {
                if let Some(tid) = first_rec.p_container.0.get("tenant_id") {
                    tenant_id = Some(tid.clone());
                }
                if let Some(pn) = first_rec.p_container.0.get("policy_name") {
                    policy_name = Some(pn.clone());
                }
                if let Some(pv) = first_rec.p_container.0.get("policy_version") {
                    policy_version = Some(pv.clone());
                }
                if let Some(pd) = first_rec.p_container.0.get("policy_decision") {
                    policy_decision = Some(pd.clone());
                }
            }

            // Best-effort write to the forensics store using an S3-style path.
            match dig.to_json_string() {
                Ok(json) => {
                    let tenant_ref = tenant_id.as_deref();
                    match persist_dig_to_fs(
                        tenant_ref,
                        root_id.0,
                        dig.file_id.0,
                        dig.time_range.0,
                        dig.time_range.1,
                        &json,
                    ) {
                        Ok(path) => {
                            storage_path = Some(path);
                        }
                        Err(e) => {
                            eprintln!("failed to persist dig to forensics store: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("failed to serialize dig for forensics store: {}", e);
                }
            }

            // Compute a SNARK-friendly Merkle root over DigRecord leaf hashes
            // and encode it as hex for inclusion in the dig index.
            let snark_root = if dig.dig_records.is_empty() {
                None
            } else {
                let leaves: Vec<Hash> = dig.dig_records.iter().map(|r| r.leaf_hash()).collect();
                let fr_root = zk_snark::compute_snark_merkle_root_from_hashes(&leaves);
                Some(zk_snark::fr_to_hex(&fr_root))
            };

            let policy_commit_id = std::env::var("UTLD_POLICY_COMMIT_ID").ok();

            // Derive actor DIDs from records (unique set).
            let mut actor_dids: Vec<String> = Vec::new();
            for rec in &dig.dig_records {
                if let Some(ref did) = rec.actor_did {
                    if !actor_dids.contains(did) {
                        actor_dids.push(did.clone());
                    }
                }
            }

            let entry = DigIndexEntry {
                file_id: dig.file_id.0.to_string(),
                root_id: root_id.0.to_string(),
                tenant_id: tenant_id.clone(),
                time_start: dig.time_range.0,
                time_end: dig.time_range.1,
                record_count: dig.dig_records.len(),
                merkle_root: hex::encode(dig.merkle_root.0),
                snark_root,
                policy_name,
                policy_version,
                policy_decision,
                storage_path,
                policy_commit_id,
                prev_index_hash: None,
                svc_commits: dig.svc_commits.clone(),
                infra_version_id: None,
                camera_frames: dig.camera_frames.clone(),
                actor_dids,
                compliance_framework: None,
                compliance_burn_id: None,
                file_hash: Some(hex::encode(dig.file_hash.0)),
                compression: dig.compression.clone(),
                encryption: dig.encryption.clone(),
                signature: dig.signature.clone(),
                schema_version: dig.schema_version,
            };

            if let Err(e) = dig_index::append_index_entry(&entry) {
                eprintln!("failed to append dig index entry: {}", e);
            }

            // Optional business usage hook: emit one DigFiles usage event per
            // sealed dig when a tenant_id is available.
            if let Some(plugin_arc) = plugin.as_ref() {
                if let Some(tid) = tenant_id {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let usage = UsageEvent {
                        ts: now,
                        tenant_id: tid,
                        product: ProductId::ManagedUtldClusters,
                        metric: MetricKind::DigFiles,
                        quantity: 1,
                        root_id: Some(root_id),
                        entity_id: None,
                        note: Some("sealed_dig".to_string()),
                    };

                    plugin_arc.on_usage_event(&usage);
                }
            }
        }
        Err(e) => {
            eprintln!("failed to seal dig for root {:?}: {:?}", root_id, e);
        }
    }
}

fn persist_dig_file(root_id: UID, dig: &dig_mem::DigFile) -> std::io::Result<()> {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let base = std::env::var("UTLD_DIG_DIR").unwrap_or_else(|_| "./dig".to_string());
    let mut path = PathBuf::from(base);
    fs::create_dir_all(&path)?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let filename = format!("root-{}_file-{}_{}.dig.json", root_id.0, dig.file_id.0, ts);
    path.push(&filename);

    let json = dig.to_json_string()?;

    // Atomic write: temp file + fsync + rename.
    let mut tmp_path = path.clone();
    tmp_path.set_extension("tmp");
    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, &path)?;

    // Optional HMAC-SHA256 signature over the JSON, if UTLD_DIG_SIGN_KEY is set.
    if let Ok(key_hex) = std::env::var("UTLD_DIG_SIGN_KEY") {
        if let Ok(key_bytes) = hex::decode(&key_hex) {
            if let Ok(mut mac) = HmacSha256::new_from_slice(&key_bytes) {
                mac.update(json.as_bytes());
                let sig = mac.finalize().into_bytes();
                let mut sig_path = path.clone();
                sig_path.set_extension("sig");
                let sig_hex = hex::encode(sig);
                let mut sig_file = File::create(&sig_path)?;
                sig_file.write_all(sig_hex.as_bytes())?;
                sig_file.sync_all()?;
            } else {
                eprintln!("failed to create HMAC from UTLD_DIG_SIGN_KEY; skipping dig signing");
            }
        } else {
            eprintln!("UTLD_DIG_SIGN_KEY is not valid hex; skipping dig signing");
        }
    }

    Ok(())
}

fn handle_client(
    stream: UnixStream,
    node: Arc<Mutex<UtlNode>>,
    engine: Option<Arc<Mutex<PolicyEngine>>>,
    plugin: Option<Arc<dyn BusinessPlugin + Send + Sync>>,
) -> std::io::Result<()> {
    handle_client_generic(stream, node, engine, plugin, None)
}

/// Generic client handler that optionally injects a DID into p_container.
pub fn handle_client_with_did<S: std::io::Read + std::io::Write>(
    stream: S,
    node: Arc<Mutex<UtlNode>>,
    engine: Option<Arc<Mutex<PolicyEngine>>>,
    plugin: Option<Arc<dyn BusinessPlugin + Send + Sync>>,
    peer_did: Option<security_os::Did>,
) -> std::io::Result<()> {
    handle_client_generic(stream, node, engine, plugin, peer_did)
}

fn handle_client_generic<S>(
    mut stream: S,
    node: Arc<Mutex<UtlNode>>,
    engine: Option<Arc<Mutex<PolicyEngine>>>,
    plugin: Option<Arc<dyn BusinessPlugin + Send + Sync>>,
    peer_did: Option<security_os::Did>,
) -> std::io::Result<()>
where
    S: std::io::Read + std::io::Write,
{
    let mut buffer = String::new();

    #[cfg(feature = "bar_governance")]
    let mut bar_gov = BarGovernance::default();

    loop {
        buffer.clear();

        // Read a single line from the stream (blocking) into buffer.
        let mut n_total = 0usize;
        loop {
            let mut byte = [0u8; 1];
            let n = stream.read(&mut byte)?;
            if n == 0 {
                break;
            }
            n_total += n;
            let b = byte[0];
            buffer.push(b as char);
            if b == b'\n' {
                break;
            }
        }

        if n_total == 0 {
            // EOF
            break;
        }

        let line = buffer.trim();
        if line.is_empty() {
            continue;
        }

        let mut req: NodeRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                let resp = NodeResponse::Error {
                    message: format!("invalid_json: {}", e),
                };
                let s = serde_json::to_string(&resp).unwrap();
                writeln!(&mut stream, "{}", s)?;
                continue;
            }
        };

        // Inject DID from TLS client cert into p_container if present.
        if let Some(ref did) = peer_did {
            if let NodeRequest::RecordTransition {
                ref mut p_container,
                ..
            } = req
            {
                let did_str = did.as_str().to_string();
                p_container
                    .entry("actor_did".to_string())
                    .or_insert_with(|| did_str.clone());
                p_container.entry("src_did".to_string()).or_insert(did_str);
            }
        }

        let resp = {
            let mut node_guard = node.lock().unwrap();

            #[cfg(feature = "bar_governance")]
            {
                if let Some(bar_resp) = bar_gov.maybe_apply(&mut req, &mut node_guard, &plugin) {
                    bar_resp
                } else {
                    if let Some(engine_arc) = engine.as_ref() {
                        let mut eng_guard = engine_arc.lock().unwrap();
                        let mut gov = PolicyGovernance {
                            engine: &mut eng_guard,
                        };
                        if let Some(policy_resp) =
                            gov.maybe_apply(&mut req, &mut node_guard, &plugin)
                        {
                            policy_resp
                        } else {
                            handle_request(&mut node_guard, req)
                        }
                    } else {
                        handle_request(&mut node_guard, req)
                    }
                }
            }

            #[cfg(not(feature = "bar_governance"))]
            {
                if let Some(engine_arc) = engine.as_ref() {
                    let mut eng_guard = engine_arc.lock().unwrap();
                    let mut gov = PolicyGovernance {
                        engine: &mut eng_guard,
                    };
                    if let Some(policy_resp) = gov.maybe_apply(&mut req, &mut node_guard, &plugin) {
                        policy_resp
                    } else {
                        handle_request(&mut node_guard, req)
                    }
                } else {
                    handle_request(&mut node_guard, req)
                }
            }
        };
        let s = serde_json::to_string(&resp).unwrap();
        writeln!(&mut stream, "{}", s)?;
    }

    Ok(())
}

/// Emit a truth snapshot event capturing current system state heads
fn emit_truth_snapshot(tenant_id: Option<String>, trigger: &str) {
    let dig_index_head = compute_dig_index_head();
    let policy_ledger_head = compute_policy_ledger_head();

    let snapshot_event = DecisionEvent {
        ts: 0, // Will be set by append_decision_event
        tenant_id,
        root_id: "snapshot".to_string(),
        entity_id: trigger.to_string(),
        event_kind: "truth_snapshot".to_string(),
        policy_name: Some("system".to_string()),
        policy_version: Some("1.0".to_string()),
        policy_commit_id: Some(policy_ledger_head.clone()),
        policy_decision: "snapshot_created".to_string(),
        policy_rules: vec!["truth_snapshot".to_string()],
        policy_actions: vec!["record_state".to_string()],
        src_did: Some(dig_index_head.clone()),
        dst_did: Some(policy_ledger_head),
        actor_did: Some("utld".to_string()),
        src_zone: Some("system".to_string()),
        dst_zone: Some("audit".to_string()),
        snark_high_threat_merkle_status: None,
        schema_version: 1,
        prev_hash: None,
        record_hash: None,
        consensus_decision: None,
        consensus_threshold_met: None,
        consensus_quorum_reached: None,
        consensus_total_weight: None,
        consensus_hash: None,
        consensus_validator_count: None,
        svc_policy_id: None,
        svc_infra_id: None,
    };

    if let Err(e) = append_decision_event(&snapshot_event) {
        eprintln!("Warning: failed to emit truth snapshot: {}", e);
    } else {
        eprintln!("Truth snapshot emitted: trigger={}", trigger);
    }
}

fn compute_dig_index_head() -> String {
    // Try SQLite first
    if let Ok(db_path) = std::env::var("UTLD_DIG_INDEX_DB") {
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            if let Ok(mut stmt) =
                conn.prepare("SELECT file_id FROM digs ORDER BY time_start DESC LIMIT 1")
            {
                if let Ok(row) = stmt.query_row([], |row| row.get::<_, String>(0)) {
                    return format!("sqlite:{}", row);
                }
            }
        }
    }

    // Fall back to JSONL head file
    if let Ok(path) = std::env::var("UTLD_DIG_INDEX") {
        let head_path = format!("{}.head", path);
        if let Ok(content) = std::fs::read_to_string(&head_path) {
            return content.trim().to_string();
        }
    }

    "unknown".to_string()
}

fn compute_policy_ledger_head() -> String {
    if let Ok(path) = std::env::var("UTLD_POLICY_LEDGER") {
        let head_path = format!("{}.head", path);
        if let Ok(content) = std::fs::read_to_string(&head_path) {
            return content.trim().to_string();
        }
    }

    // Compute from policy commit ID env if available
    if let Ok(commit) = std::env::var("UTLD_POLICY_COMMIT_ID") {
        return commit;
    }

    "unknown".to_string()
}
