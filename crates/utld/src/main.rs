use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use core_types::{Hash, UID};
use forensics_store::persist_dig_to_fs;
use biz_api::{BusinessPlugin, UsageEvent, ProductId, MetricKind};
use security_events::{append_decision_event, DecisionEvent};
use policy_engine::{EngineAction, EngineEvent, PolicyEngine, Value as EngineValue};
use truthscript::{Action as PolicyAction, Policy};
use zk_snark::{self, Fr as SnarkFr};
use utld::{handle_request, NodeRequest, NodeResponse, UtlNode};
use sot_root::StateOfTruthRoot;
use serde::Deserialize;
use dig_index::DigIndexEntry;

struct FileBusinessPlugin {
    path: String,
}

impl FileBusinessPlugin {
    fn new(path: String) -> Self {
        Self { path }
    }
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

    let plugin: Option<Arc<dyn BusinessPlugin + Send + Sync>> = if sinks.is_empty() {
        None
    } else {
        Some(Arc::new(CompositeBusinessPlugin::new(sinks)))
    };

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
            fields.insert("entity_id".to_string(), EngineValue::String(entity_id.to_string()));
            fields.insert("root_id".to_string(), EngineValue::String(root_id.to_string()));
            fields.insert("logic_ref".to_string(), EngineValue::String(logic_ref.clone()));

            for (k, v) in p_container.iter() {
                if let Ok(n) = v.parse::<f64>() {
                    fields.insert(k.clone(), EngineValue::Number(n));
                } else {
                    fields.insert(k.clone(), EngineValue::String(v.clone()));
                }
            }

            let kind = p_container
                .get("event_kind")
                .cloned()
                .unwrap_or_else(|| "record_transition".to_string());

            let event = EngineEvent { kind: kind.clone(), fields };
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
                                snark_status = run_high_threat_merkle_snark(node, UID(*root_id), rule_name);
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

                let mut event_rec = DecisionEvent {
                    ts: 0,
                    tenant_id,
                    root_id: root_id.to_string(),
                    entity_id: entity_id.to_string(),
                    event_kind: kind.clone(),
                    policy_name: Some(policy_name.to_string()),
                    policy_version: Some(policy_version.to_string()),
                    policy_decision: decision.clone(),
                    policy_rules: rule_names.clone(),
                    policy_actions: action_kinds.clone(),
                    src_did,
                    dst_did,
                    actor_did,
                    src_zone,
                    dst_zone,
                    snark_high_threat_merkle_status: snark_status,
                };

                if let Err(e) = append_decision_event(&event_rec) {
                    eprintln!("failed to append decision event: {}", e);
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
                                .and_then(|proof| zk_snark::verify_equality(&keys, &proof, x)) {
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
            | PolicyAction::FlagForInvestigation { .. }
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
                            eprintln!("failed to generate micro-proof for root {:?}: {:?}", root_id, e);
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
                                        rule_name,
                                        score_scaled,
                                        last_index,
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
                                rule_name,
                                e,
                            );
                        }
                    }
                } else {
                    eprintln!(
                        "snark_high_threat_merkle_path_error (rule={} root_id={} index={})",
                        rule_name,
                        root_id.0,
                        last_index,
                    );
                }
            } else {
                eprintln!("snark_high_threat_merkle_no_records (rule={} root_id={})", rule_name, root_id.0);
            }
        } else {
            eprintln!("snark_high_threat_merkle_missing_records (rule={} root_id={})", rule_name, root_id.0);
        }
    } else {
        eprintln!("snark_high_threat_missing_score (rule={} root_id={})", rule_name, root_id.0);
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

            if let Some(first_rec) = dig.dig_records.get(0) {
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
                prev_index_hash: None,
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

    let filename = format!(
        "root-{}_file-{}_{}.dig.json",
        root_id.0,
        dig.file_id.0,
        ts
    );
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
    let reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        let mut req: NodeRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = NodeResponse::Error {
                    message: format!("invalid_json: {}", e),
                };
                let s = serde_json::to_string(&resp).unwrap();
                writeln!(writer, "{}", s)?;
                continue;
            }
        };

        let resp = {
            let mut node_guard = node.lock().unwrap();
            if let Some(engine_arc) = engine.as_ref() {
                let mut eng_guard = engine_arc.lock().unwrap();
                if let Some(policy_resp) = enforce_policy(&mut *eng_guard, &mut req, &mut *node_guard, &plugin) {
                    policy_resp
                } else {
                    handle_request(&mut *node_guard, req)
                }
            } else {
                handle_request(&mut *node_guard, req)
            }
        };
        let s = serde_json::to_string(&resp).unwrap();
        writeln!(writer, "{}", s)?;
    }

    Ok(())
}
