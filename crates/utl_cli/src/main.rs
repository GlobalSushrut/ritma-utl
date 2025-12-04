use std::collections::BTreeMap;
use std::io::BufRead;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use dig_mem::DigFile;
use dig_index::DigIndexEntry;
use policy_engine::{EngineEvent, PolicyEngine, Value as EngineValue};
use tenant_policy::{Lawbook, validate_lawbook};
use truthscript::Policy as TsPolicy;
use utl_client::UtlClient;
use utld::{NodeRequest, NodeResponse};

#[derive(Parser)]
#[command(name = "utl", about = "Universal Truth Layer CLI", version)]
struct Cli {
    /// Path to the utld Unix socket (defaults to UTLD_SOCKET or /tmp/utld.sock).
    #[arg(short, long)]
    socket: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List registered StateOfTruth roots.
    RootsList,

    /// Register a new StateOfTruth root.
    RootRegister {
        /// Root identifier (u128 as decimal).
        #[arg(long)]
        root_id: u128,
        /// Root hash (32-byte hex).
        #[arg(long)]
        root_hash: String,
        /// Transition hook id (u128, decimal). Defaults to root_id.
        #[arg(long)]
        tx_hook: Option<u128>,
        /// Root parameters as key=value pairs.
        #[arg(long = "param", value_parser = parse_kv)]
        params: Vec<(String, String)>,
    },

    /// Record a transition event.
    TxRecord {
        #[arg(long)]
        entity_id: u128,
        #[arg(long)]
        root_id: u128,
        /// Signature bytes (hex).
        #[arg(long)]
        signature: String,
        /// Data payload (UTF-8 string).
        #[arg(long)]
        data: String,
        /// Address/heap hash (32-byte hex).
        #[arg(long)]
        addr_heap_hash: String,
        /// Hook hash (32-byte hex).
        #[arg(long)]
        hook_hash: String,
        /// Logic ref string.
        #[arg(long)]
        logic_ref: String,
        /// Boundary tag / wall string.
        #[arg(long)]
        wall: String,
        /// Parameters as key=value pairs.
        #[arg(long = "param", value_parser = parse_kv)]
        params: Vec<(String, String)>,
    },

    /// Build a DigFile summary for a root.
    DigBuild {
        #[arg(long)]
        root_id: u128,
        #[arg(long)]
        file_id: u128,
        #[arg(long)]
        time_start: u64,
        #[arg(long)]
        time_end: u64,
    },

    /// Build an entropy bin for a root.
    EntropyBin {
        #[arg(long)]
        root_id: u128,
        #[arg(long)]
        bin_id: u128,
    },

    /// Validate a TruthScript policy file (JSON) for syntax/structure.
    PolicyValidate {
        /// Path to policy JSON file.
        #[arg(long)]
        file: String,
    },

    /// Test a TruthScript policy file against a synthetic event.
    PolicyTest {
        /// Path to policy JSON file.
        #[arg(long)]
        file: String,
        /// Event kind.
        #[arg(long)]
        kind: String,
        /// Event fields as key=value pairs.
        #[arg(long = "field", value_parser = parse_kv)]
        fields: Vec<(String, String)>,
    },

    /// Validate a tenant lawbook JSON file against platform invariants.
    LawbookValidate {
        /// Path to lawbook JSON file.
        #[arg(long)]
        file: String,
    },

    /// Inspect a persisted DigFile (.dig.json) and print a human summary.
    DigInspect {
        /// Path to DigFile JSON.
        #[arg(long)]
        file: String,
        /// Maximum number of records to print.
        #[arg(long, default_value_t = 5)]
        limit: usize,
        /// Optional tenant_id filter.
        #[arg(long)]
        tenant: Option<String>,
        /// Optional event_kind filter.
        #[arg(long)]
        event_kind: Option<String>,
        /// Optional severity filter.
        #[arg(long)]
        severity: Option<String>,
    },

    /// Inspect a DigFile by file_id using the local dig index.
    DigInspectId {
        /// DigFile ID (decimal string as printed by digs-list).
        #[arg(long)]
        file_id: String,
        /// Optional root_id filter (decimal string) to disambiguate.
        #[arg(long)]
        root_id: Option<String>,
        /// Maximum number of records to print.
        #[arg(long, default_value_t = 5)]
        limit: usize,
        /// Optional tenant_id filter.
        #[arg(long)]
        tenant: Option<String>,
        /// Optional event_kind filter.
        #[arg(long)]
        event_kind: Option<String>,
        /// Optional severity filter.
        #[arg(long)]
        severity: Option<String>,
    },

    /// List DigFiles from the local dig index (dig_index.jsonl).
    DigsList {
        /// Optional tenant_id filter.
        #[arg(long)]
        tenant: Option<String>,
        /// Optional root_id filter (decimal string).
        #[arg(long)]
        root_id: Option<String>,
        /// Maximum number of entries to print.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Try to resolve and print the underlying DigFile path from UTLD_DIG_DIR/./dig.
        #[arg(long)]
        show_path: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let socket = cli
        .socket
        .unwrap_or_else(|| std::env::var("UTLD_SOCKET").unwrap_or_else(|_| "/tmp/utld.sock".to_string()));

    let client = UtlClient::new(socket);

    let result = match cli.command {
        Commands::RootsList => cmd_roots_list(&client),
        Commands::RootRegister {
            root_id,
            root_hash,
            tx_hook,
            params,
        } => cmd_root_register(&client, root_id, &root_hash, tx_hook, params),
        Commands::TxRecord {
            entity_id,
            root_id,
            signature,
            data,
            addr_heap_hash,
            hook_hash,
            logic_ref,
            wall,
            params,
        } => cmd_tx_record(
            &client,
            entity_id,
            root_id,
            &signature,
            &data,
            &addr_heap_hash,
            &hook_hash,
            &logic_ref,
            &wall,
            params,
        ),
        Commands::DigBuild {
            root_id,
            file_id,
            time_start,
            time_end,
        } => cmd_dig_build(&client, root_id, file_id, time_start, time_end),
        Commands::EntropyBin { root_id, bin_id } => cmd_entropy_bin(&client, root_id, bin_id),
        Commands::PolicyValidate { file } => cmd_policy_validate(&file),
        Commands::PolicyTest { file, kind, fields } => cmd_policy_test(&file, &kind, fields),
        Commands::DigInspect {
            file,
            limit,
            tenant,
            event_kind,
            severity,
        } => cmd_dig_inspect(
            &file,
            limit,
            tenant.as_deref(),
            event_kind.as_deref(),
            severity.as_deref(),
        ),
        Commands::DigInspectId {
            file_id,
            root_id,
            limit,
            tenant,
            event_kind,
            severity,
        } => cmd_dig_inspect_id(
            &file_id,
            root_id.as_deref(),
            limit,
            tenant.as_deref(),
            event_kind.as_deref(),
            severity.as_deref(),
        ),
        Commands::LawbookValidate { file } => cmd_lawbook_validate(&file),
        Commands::DigsList { tenant, root_id, limit, show_path } => cmd_digs_list(
            tenant.as_deref(),
            root_id.as_deref(),
            limit,
            show_path,
        ),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::from(1)
        }
    }
}

fn cmd_roots_list(client: &UtlClient) -> Result<(), String> {
    let resp = client.send(&NodeRequest::ListRoots).map_err(err_to_string)?;
    match resp {
        NodeResponse::Roots { root_ids } => {
            for id in root_ids {
                println!("{}", id);
            }
            Ok(())
        }
        other => Err(format!("unexpected response: {:?}", other)),
    }
}

fn cmd_root_register(
    client: &UtlClient,
    root_id: u128,
    root_hash_hex: &str,
    tx_hook: Option<u128>,
    params: Vec<(String, String)>,
) -> Result<(), String> {
    let root_hash = parse_hash32(root_hash_hex).map_err(|e| format!("invalid root_hash: {}", e))?;
    let tx_hook = tx_hook.unwrap_or(root_id);
    let mut root_params = BTreeMap::new();
    for (k, v) in params {
        root_params.insert(k, v);
    }

    let req = NodeRequest::RegisterRoot {
        root_id,
        root_hash,
        root_params,
        tx_hook,
        zk_arc_commit: Vec::new(),
    };

    match client.send(&req).map_err(err_to_string)? {
        NodeResponse::Ok => {
            println!("root registered: {}", root_id);
            Ok(())
        }
        other => Err(format!("unexpected response: {:?}", other)),
    }
}

fn cmd_tx_record(
    client: &UtlClient,
    entity_id: u128,
    root_id: u128,
    signature_hex: &str,
    data_str: &str,
    addr_heap_hash_hex: &str,
    hook_hash_hex: &str,
    logic_ref: &str,
    wall: &str,
    params: Vec<(String, String)>,
) -> Result<(), String> {
    let signature = hex::decode(signature_hex).map_err(|e| format!("invalid signature hex: {}", e))?;
    let data = data_str.as_bytes().to_vec();
    let addr_heap_hash = parse_hash32(addr_heap_hash_hex).map_err(|e| format!("invalid addr_heap_hash: {}", e))?;
    let hook_hash = parse_hash32(hook_hash_hex).map_err(|e| format!("invalid hook_hash: {}", e))?;

    let mut p_container = BTreeMap::new();
    for (k, v) in params {
        p_container.insert(k, v);
    }

    let req = NodeRequest::RecordTransition {
        entity_id,
        root_id,
        signature,
        data,
        addr_heap_hash,
        p_container,
        logic_ref: logic_ref.to_string(),
        wall: wall.to_string(),
        hook_hash,
    };

    match client.send(&req).map_err(err_to_string)? {
        NodeResponse::Ok => {
            println!("transition recorded for root {}", root_id);
            Ok(())
        }
        other => Err(format!("unexpected response: {:?}", other)),
    }
}

fn cmd_dig_build(
    client: &UtlClient,
    root_id: u128,
    file_id: u128,
    time_start: u64,
    time_end: u64,
) -> Result<(), String> {
    let req = NodeRequest::BuildDigFile {
        root_id,
        file_id,
        time_start,
        time_end,
    };

    match client.send(&req).map_err(err_to_string)? {
        NodeResponse::DigFileSummary {
            root_id,
            file_id,
            merkle_root,
            record_count,
        } => {
            println!("root_id: {}", root_id);
            println!("file_id: {}", file_id);
            println!("merkle_root: {}", hex::encode(merkle_root));
            println!("record_count: {}", record_count);
            Ok(())
        }
        other => Err(format!("unexpected response: {:?}", other)),
    }
}

fn cmd_entropy_bin(client: &UtlClient, root_id: u128, bin_id: u128) -> Result<(), String> {
    let req = NodeRequest::BuildEntropyBin { root_id, bin_id };

    match client.send(&req).map_err(err_to_string)? {
        NodeResponse::EntropyBinSummary {
            root_id,
            bin_id,
            local_entropy,
        } => {
            println!("root_id: {}", root_id);
            println!("bin_id: {}", bin_id);
            println!("local_entropy: {}", local_entropy);
            Ok(())
        }
        other => Err(format!("unexpected response: {:?}", other)),
    }
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err("expected key=value".to_string());
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn parse_hash32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn err_to_string(err: impl std::fmt::Debug) -> String {
    format!("{:?}", err)
}

fn cmd_dig_inspect(
    path: &str,
    limit: usize,
    tenant: Option<&str>,
    event_kind: Option<&str>,
    severity: Option<&str>,
) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read dig file {}: {}", path, e))?;

    let dig: DigFile = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse dig file {}: {}", path, e))?;

    println!("file_id: {}", dig.file_id.0);
    println!("time_range: {} - {}", dig.time_range.0, dig.time_range.1);
    println!("record_count: {}", dig.dig_records.len());
    println!("merkle_root: {}", hex::encode(dig.merkle_root.0));

    let matches: Vec<(usize, &dig_mem::DigRecord)> = dig
        .dig_records
        .iter()
        .enumerate()
        .filter(|(_, rec)| {
            let params = &rec.p_container.0;

            if let Some(t) = tenant {
                if params.get("tenant_id").map(String::as_str) != Some(t) {
                    return false;
                }
            }

            if let Some(k) = event_kind {
                if params.get("event_kind").map(String::as_str) != Some(k) {
                    return false;
                }
            }

            if let Some(s) = severity {
                if params.get("severity").map(String::as_str) != Some(s) {
                    return false;
                }
            }

            true
        })
        .collect();

    println!("matching_records: {}", matches.len());

    let max = limit.min(matches.len());
    for (idx, (orig_idx, rec)) in matches.into_iter().take(max).enumerate() {
        let params = &rec.p_container.0;
        let kind = params
            .get("event_kind")
            .cloned()
            .unwrap_or_else(|| "<none>".to_string());
        let sev = params
            .get("severity")
            .cloned()
            .unwrap_or_else(|| "<none>".to_string());
        let tenant_id = params
            .get("tenant_id")
            .cloned()
            .unwrap_or_else(|| "<none>".to_string());
        let decision = params
            .get("policy_decision")
            .cloned()
            .unwrap_or_else(|| "<none>".to_string());
        let policy_name = params
            .get("policy_name")
            .cloned()
            .unwrap_or_else(|| "<none>".to_string());
        let policy_rules = params
            .get("policy_rules")
            .cloned()
            .unwrap_or_else(|| "<none>".to_string());

        println!(
            "record[{}] (orig index {}): event_kind={} severity={} tenant_id={} decision={} policy={} rules={}",
            idx, orig_idx, kind, sev, tenant_id, decision, policy_name, policy_rules
        );
    }

    Ok(())
}

fn cmd_dig_inspect_id(
    file_id: &str,
    root_id: Option<&str>,
    limit: usize,
    tenant: Option<&str>,
    event_kind: Option<&str>,
    severity: Option<&str>,
) -> Result<(), String> {
    let index_path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let file = std::fs::File::open(&index_path)
        .map_err(|e| format!("failed to open dig index {}: {}", index_path, e))?;

    let reader = std::io::BufReader::new(file);
    let mut matched: Option<DigIndexEntry> = None;

    for line_result in reader.lines() {
        let line = line_result
            .map_err(|e| format!("error reading dig index {}: {}", index_path, e))?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: DigIndexEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping malformed index entry: {}", e);
                continue;
            }
        };

        if entry.file_id != file_id {
            continue;
        }

        if let Some(r) = root_id {
            if entry.root_id.as_str() != r {
                continue;
            }
        }

        matched = Some(entry);
        break;
    }

    let entry = matched.ok_or_else(|| {
        format!("no dig index entry found for file_id={} root_id={:?}", file_id, root_id)
    })?;

    let base_dir = std::env::var("UTLD_DIG_DIR").unwrap_or_else(|_| "./dig".to_string());
    let pattern = format!("root-{}_file-{}_", entry.root_id, entry.file_id);

    let mut resolved_path = None;
    if let Ok(dir_entries) = std::fs::read_dir(&base_dir) {
        for entry_fs in dir_entries.flatten() {
            if let Ok(name) = entry_fs.file_name().into_string() {
                if name.starts_with(&pattern) && name.ends_with(".dig.json") {
                    resolved_path = Some(format!("{}/{}", base_dir, name));
                    break;
                }
            }
        }
    }

    let path = resolved_path.ok_or_else(|| {
        format!(
            "could not resolve DigFile path for file_id={} root_id={}",
            entry.file_id, entry.root_id
        )
    })?;

    cmd_dig_inspect(&path, limit, tenant, event_kind, severity)
}

fn cmd_digs_list(
    tenant: Option<&str>,
    root_id: Option<&str>,
    limit: usize,
    show_path: bool,
) -> Result<(), String> {
    let path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("failed to open dig index {}: {}", path, e))?;

    let reader = std::io::BufReader::new(file);
    let mut printed = 0usize;

    for line_result in reader.lines() {
        let line = line_result.map_err(|e| format!("error reading dig index {}: {}", path, e))?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: DigIndexEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping malformed index entry: {}", e);
                continue;
            }
        };

        if let Some(t) = tenant {
            if entry.tenant_id.as_deref() != Some(t) {
                continue;
            }
        }

        if let Some(r) = root_id {
            if entry.root_id.as_str() != r {
                continue;
            }
        }

        if show_path {
            let base_dir = std::env::var("UTLD_DIG_DIR").unwrap_or_else(|_| "./dig".to_string());
            let pattern = format!("root-{}_file-{}_", entry.root_id, entry.file_id);

            let mut resolved_path = "<not-found>".to_string();
            if let Ok(dir_entries) = std::fs::read_dir(&base_dir) {
                for entry_fs in dir_entries.flatten() {
                    if let Ok(name) = entry_fs.file_name().into_string() {
                        if name.starts_with(&pattern) && name.ends_with(".dig.json") {
                            resolved_path = format!("{}/{}", base_dir, name);
                            break;
                        }
                    }
                }
            }

            println!(
                "file_id={} root_id={} tenant_id={} time_range={}-{} records={} merkle_root={} policy={} decision={} path={}",
                entry.file_id,
                entry.root_id,
                entry.tenant_id.as_deref().unwrap_or("<none>"),
                entry.time_start,
                entry.time_end,
                entry.record_count,
                entry.merkle_root,
                entry.policy_name.as_deref().unwrap_or("<none>"),
                entry.policy_decision.as_deref().unwrap_or("<none>"),
                resolved_path,
            );
        } else {
            println!(
                "file_id={} root_id={} tenant_id={} time_range={}-{} records={} merkle_root={} policy={} decision={}",
                entry.file_id,
                entry.root_id,
                entry.tenant_id.as_deref().unwrap_or("<none>"),
                entry.time_start,
                entry.time_end,
                entry.record_count,
                entry.merkle_root,
                entry.policy_name.as_deref().unwrap_or("<none>"),
                entry.policy_decision.as_deref().unwrap_or("<none>"),
            );
        }

        printed += 1;
        if printed >= limit {
            break;
        }
    }

    if printed == 0 {
        println!("no dig index entries matched the filters");
    }

    Ok(())
}

fn cmd_policy_validate(path: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read policy file {}: {}", path, e))?;

    match TsPolicy::from_json_str(&content) {
        Ok(policy) => {
            println!(
                "policy '{}' v{} loaded (rules={})",
                policy.name,
                policy.version,
                policy.rules.len()
            );
            Ok(())
        }
        Err(e) => Err(format!("policy parse error: {}", e)),
    }
}

fn cmd_lawbook_validate(path: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read lawbook file {}: {}", path, e))?;

    let lb: Lawbook = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse lawbook file {}: {}", path, e))?;

    validate_lawbook(&lb)?;

    println!(
        "lawbook ok: tenant_id={} policy_id={} version={} rules={}",
        lb.tenant_id,
        lb.policy_id,
        lb.version,
        lb.rules.len()
    );

    Ok(())
}

fn cmd_policy_test(path: &str, kind: &str, fields: Vec<(String, String)>) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read policy file {}: {}", path, e))?;

    let policy = TsPolicy::from_json_str(&content)
        .map_err(|e| format!("policy parse error: {}", e))?;

    let mut engine = PolicyEngine::new(policy);
    let mut map = BTreeMap::new();
    for (k, v) in fields {
        let val = if v.eq_ignore_ascii_case("true") {
            EngineValue::Bool(true)
        } else if v.eq_ignore_ascii_case("false") {
            EngineValue::Bool(false)
        } else if let Ok(n) = v.parse::<f64>() {
            EngineValue::Number(n)
        } else {
            EngineValue::String(v)
        };
        map.insert(k, val);
    }

    let event = EngineEvent {
        kind: kind.to_string(),
        fields: map,
    };

    let actions = engine.evaluate(&event);
    if actions.is_empty() {
        println!("no actions fired");
    } else {
        println!("actions fired:");
        for a in actions {
            println!("- rule={} action={:?}", a.rule_name, a.action);
        }
    }

    Ok(())
}
