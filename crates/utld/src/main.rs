use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use core_types::UID;
use forensics_store::persist_dig_to_fs;
use security_events::{append_decision_event, DecisionEvent};
use policy_engine::{EngineAction, EngineEvent, PolicyEngine, Value as EngineValue};
use truthscript::{Action as PolicyAction, Policy};
use zk_snark::{self, Fr as SnarkFr};
use utld::{handle_request, NodeRequest, NodeResponse, UtlNode};
use sot_root::StateOfTruthRoot;
use serde::{Serialize, Deserialize};
use dig_index::DigIndexEntry;

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

    let mut engine = load_policy_from_env()
        .map(PolicyEngine::new);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_client(stream, &mut node, engine.as_mut()) {
                    eprintln!("client error: {}", e);
                }
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

fn enforce_policy(engine: &mut PolicyEngine, req: &mut NodeRequest, node: &mut UtlNode) -> Option<NodeResponse> {
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
                    };
                    action_kinds.push(kind_str.to_string());
                }

                // Emit a structured decision event for external consumers.
                let tenant_id = p_container.get("tenant_id").cloned();
                let src_did = p_container.get("src_did").cloned();
                let dst_did = p_container.get("dst_did").cloned();
                let actor_did = p_container.get("actor_did").cloned();
                let src_zone = p_container.get("src_zone").cloned();
                let dst_zone = p_container.get("dst_zone").cloned();

                let event_rec = DecisionEvent {
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
                };

                if let Err(e) = append_decision_event(&event_rec) {
                    eprintln!("failed to append decision event: {}", e);
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

            apply_engine_actions(actions, node, *root_id)
        }
        _ => None,
    }
}

fn apply_engine_actions(actions: Vec<EngineAction>, node: &mut UtlNode, root_id_raw: u128) -> Option<NodeResponse> {
    let root_id = UID(root_id_raw);

    for EngineAction { rule_name, action } in &actions {
        match action {
            PolicyAction::Deny { reason } => {
                seal_and_index_current_dig(node, root_id);
                let msg = format!("denied_by_policy({}): {}", rule_name, reason);
                return Some(NodeResponse::Error { message: msg });
            }
            PolicyAction::SealCurrentDig => {
                seal_and_index_current_dig(node, root_id);
            }
            PolicyAction::RequireSnarkProof => {
                // Demo: generate and verify a Groth16 equality proof using root_id
                // mapped into the scalar field.
                let circuit_id = UID::new();
                match zk_snark::setup_equality(circuit_id) {
                    Ok(keys) => {
                        let a = SnarkFr::from(root_id.0 as u64);
                        let b = a;
                        match zk_snark::prove_equality(&keys, a, b)
                            .and_then(|proof| zk_snark::verify_equality(&keys, &proof))
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

fn seal_and_index_current_dig(node: &mut UtlNode, root_id: UID) {
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

            let entry = DigIndexEntry {
                file_id: dig.file_id.0.to_string(),
                root_id: root_id.0.to_string(),
                tenant_id,
                time_start: dig.time_range.0,
                time_end: dig.time_range.1,
                record_count: dig.dig_records.len(),
                merkle_root: hex::encode(dig.merkle_root.0),
                policy_name,
                policy_version,
                policy_decision,
                storage_path,
            };

            if let Err(e) = dig_index::append_index_entry(&entry) {
                eprintln!("failed to append dig index entry: {}", e);
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
    node: &mut UtlNode,
    mut engine: Option<&mut PolicyEngine>,
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

        let resp = if let Some(engine) = engine.as_mut() {
            if let Some(policy_resp) = enforce_policy(engine, &mut req, node) {
                policy_resp
            } else {
                handle_request(node, req)
            }
        } else {
            handle_request(node, req)
        };
        let s = serde_json::to_string(&resp).unwrap();
        writeln!(writer, "{}", s)?;
    }

    Ok(())
}
