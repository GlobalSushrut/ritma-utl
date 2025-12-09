use std::collections::BTreeMap;
use std::io::BufRead;
use std::fs::File;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use core_types::{hash_bytes, Hash, UID};
use dig_mem::DigFile;
use dig_index::DigIndexEntry;
use hmac::{Hmac, Mac};
use policy_engine::{EngineEvent, PolicyEngine, Value as EngineValue};
use sha2::Sha256;
use tenant_policy::{Lawbook, validate_lawbook};
use truthscript::Policy as TsPolicy;
use utl_client::UtlClient;
use utld::{NodeRequest, NodeResponse, PolicyBurnRequest};

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

    PolicyBurn {
        #[arg(long)]
        policy_id: String,
        #[arg(long)]
        version: u64,
        #[arg(long)]
        policy_file: String,
        #[arg(long)]
        cue_hash: Option<String>,
        #[arg(long)]
        issuer: Option<String>,
    },

    PolicyLedgerList {
        #[arg(long)]
        policy_id: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    LawbookLedgerCheck {
        #[arg(long)]
        file: String,
    },

    TruthSnapshot {
        #[arg(long)]
        entity_id: u128,
        #[arg(long)]
        root_id: u128,
    },

    /// List truth snapshot events from decision_events.jsonl.
    TruthSnapshotList {
        /// Maximum number of snapshots to print.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Verify dig index and policy ledger heads against their hash-chained contents.
    TruthSnapshotVerify,

    /// Export a truth snapshot payload (dig index head + policy ledger head) for external anchoring.
    TruthSnapshotExport,

    DigSnarkInclusion {
        #[arg(long)]
        file_id: String,
        #[arg(long)]
        root_id: Option<String>,
        #[arg(long)]
        index: usize,
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

    /// Show latest dig + SNARK status for a root from the dig index and decision events.
    RootSnarkStatus {
        /// Root identifier (decimal string as used in dig_index and decision events).
        #[arg(long)]
        root_id: String,
    },

    /// List decision events from decision_events.jsonl with optional SNARK status filter.
    DecisionEventsList {
        /// Optional snark_high_threat_merkle_status filter (ok, invalid, error).
        #[arg(long)]
        snark_status: Option<String>,
        /// Maximum number of events to print.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Summarize local usage (decisions, DigFiles) per tenant from logs.
    UsageReport {
        /// Optional tenant_id filter.
        #[arg(long)]
        tenant: Option<String>,
    },

    /// Summarize file-based UsageEvent JSONL stream (UTLD_USAGE_EVENTS) per tenant/product/metric.
    UsageEventsReport {
        /// Optional tenant_id filter.
        #[arg(long)]
        tenant: Option<String>,
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
        Commands::PolicyBurn { policy_id, version, policy_file, cue_hash, issuer } => cmd_policy_burn(
            &client,
            &policy_id,
            version,
            &policy_file,
            cue_hash.as_deref(),
            issuer.as_deref(),
        ),
        Commands::PolicyLedgerList { policy_id, limit } => cmd_policy_ledger_list(
            policy_id.as_deref(),
            limit,
        ),
        Commands::LawbookLedgerCheck { file } => cmd_lawbook_ledger_check(&file),
        Commands::TruthSnapshot { entity_id, root_id } => cmd_truth_snapshot(
            &client,
            entity_id,
            root_id,
        ),
        Commands::TruthSnapshotList { limit } => cmd_truth_snapshot_list(limit),
        Commands::TruthSnapshotVerify => cmd_truth_snapshot_verify(),
        Commands::TruthSnapshotExport => cmd_truth_snapshot_export(),
        Commands::DigSnarkInclusion { file_id, root_id, index } => cmd_dig_snark_inclusion(
            &file_id,
            root_id.as_deref(),
            index,
        ),
        Commands::DigsList { tenant, root_id, limit, show_path } => cmd_digs_list(
            tenant.as_deref(),
            root_id.as_deref(),
            limit,
            show_path,
        ),
        Commands::RootSnarkStatus { root_id } => cmd_root_snark_status(&root_id),
        Commands::DecisionEventsList { snark_status, limit } => cmd_decision_events_list(
            snark_status.as_deref(),
            limit,
        ),
        Commands::UsageReport { tenant } => cmd_usage_report(tenant.as_deref()),
        Commands::UsageEventsReport { tenant } => cmd_usage_events_report(tenant.as_deref()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::from(1)
        }
    }
}

fn cmd_root_snark_status(root_id: &str) -> Result<(), String> {
    // Latest dig index entry for this root_id.
    let index_path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let file = std::fs::File::open(&index_path)
        .map_err(|e| format!("failed to open dig index {}: {}", index_path, e))?;
    let reader = std::io::BufReader::new(file);

    let mut latest_dig: Option<DigIndexEntry> = None;
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

        if entry.root_id.as_str() != root_id {
            continue;
        }

        latest_dig = Some(entry);
    }

    if let Some(entry) = latest_dig.as_ref() {
        println!(
            "dig_index: file_id={} root_id={} tenant_id={} time_range={}-{} records={} merkle_root={} snark_root={} policy={} decision={}",
            entry.file_id,
            entry.root_id,
            entry.tenant_id.as_deref().unwrap_or("<none>"),
            entry.time_start,
            entry.time_end,
            entry.record_count,
            entry.merkle_root,
            entry.snark_root.as_deref().unwrap_or("<none>"),
            entry.policy_name.as_deref().unwrap_or("<none>"),
            entry.policy_decision.as_deref().unwrap_or("<none>"),
        );
    } else {
        println!("no dig index entries found for root_id={}", root_id);
    }

    // Latest decision event (by ts) for this root_id with SNARK status.
    let events_path = std::env::var("UTLD_DECISION_EVENTS")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());
    let file = match std::fs::File::open(&events_path) {
        Ok(f) => f,
        Err(e) => {
            println!("no decision events file {}: {}", events_path, e);
            return Ok(());
        }
    };
    let reader = std::io::BufReader::new(file);

    let mut latest_ts: u64 = 0;
    let mut latest_event: Option<serde_json::Value> = None;

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("failed to read line from {}: {}", events_path, e);
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let ev: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("failed to parse decision event JSON: {}", e);
                continue;
            }
        };

        let ev_root = ev
            .get("root_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if ev_root != root_id {
            continue;
        }

        let ts = ev
            .get("ts")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if ts >= latest_ts {
            latest_ts = ts;
            latest_event = Some(ev);
        }
    }

    if let Some(ev) = latest_event {
        let ts = ev.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
        let event_kind = ev
            .get("event_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>");
        let decision = ev
            .get("policy_decision")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>");
        let status = ev
            .get("snark_high_threat_merkle_status")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>");

        println!(
            "decision_event: ts={} root_id={} event_kind={} decision={} snark_high_threat_merkle_status={}",
            ts,
            root_id,
            event_kind,
            decision,
            status,
        );
    } else {
        println!("no decision events found for root_id={}", root_id);
    }

    Ok(())
}

fn cmd_usage_events_report(filter_tenant: Option<&str>) -> Result<(), String> {
    let path = std::env::var("UTLD_USAGE_EVENTS")
        .unwrap_or_else(|_| "./usage_events.jsonl".to_string());

    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            return Err(format!("failed to open usage events {}: {}", path, e));
        }
    };

    let reader = std::io::BufReader::new(file);
    let mut totals: BTreeMap<(String, String, String), u64> = BTreeMap::new();

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("failed to read line from {}: {}", path, e);
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let ev: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("failed to parse usage event JSON: {}", e);
                continue;
            }
        };

        let tenant = ev
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
            .to_string();

        if let Some(filter) = filter_tenant {
            if tenant != filter {
                continue;
            }
        }

        let product = ev
            .get("product")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
            .to_string();

        let metric = ev
            .get("metric")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
            .to_string();

        let quantity = ev
            .get("quantity")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        let key = (tenant, product, metric);
        *totals.entry(key).or_insert(0) += quantity;
    }

    println!("tenant_id,product,metric,quantity");
    for ((tenant, product, metric), qty) in totals {
        println!("{},{},{},{}", tenant, product, metric, qty);
    }

    Ok(())
}

fn cmd_usage_report(filter_tenant: Option<&str>) -> Result<(), String> {
    // Aggregate decisions per tenant from decision_events.jsonl.
    let dec_path = std::env::var("UTLD_DECISION_EVENTS")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());

    let mut decisions_per_tenant: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();

    if let Ok(file) = File::open(&dec_path) {
        let reader = std::io::BufReader::new(file);
        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("failed to read line from {}: {}", dec_path, e);
                    continue;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            let ev: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("failed to parse decision event JSON: {}", e);
                    continue;
                }
            };

            let tid = ev
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<none>")
                .to_string();

            if let Some(filter) = filter_tenant {
                if tid != filter {
                    continue;
                }
            }

            *decisions_per_tenant.entry(tid).or_insert(0) += 1;
        }
    } else {
        eprintln!("warning: no decision events file {}", dec_path);
    }

    // Aggregate DigFiles per tenant from dig_index.jsonl.
    let idx_path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let mut digs_per_tenant: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();

    if let Ok(file) = File::open(&idx_path) {
        let reader = std::io::BufReader::new(file);
        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("failed to read line from {}: {}", idx_path, e);
                    continue;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            let entry: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("failed to parse dig index JSON: {}", e);
                    continue;
                }
            };

            let tid = entry
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<none>")
                .to_string();

            if let Some(filter) = filter_tenant {
                if tid != filter {
                    continue;
                }
            }

            *digs_per_tenant.entry(tid).or_insert(0) += 1;
        }
    } else {
        eprintln!("warning: no dig index file {}", idx_path);
    }

    // Print summary.
    println!("tenant_id,decisions,dig_files");

    let mut tenants: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    tenants.extend(decisions_per_tenant.keys().cloned());
    tenants.extend(digs_per_tenant.keys().cloned());

    if let Some(filter) = filter_tenant {
        if tenants.is_empty() {
            println!("{}", filter);
            return Ok(());
        }
    }

    for tid in tenants {
        let dec = decisions_per_tenant.get(&tid).cloned().unwrap_or(0);
        let digs = digs_per_tenant.get(&tid).cloned().unwrap_or(0);
        println!("{},{},{}", tid, dec, digs);
    }

    Ok(())
}

fn cmd_decision_events_list(snark_status: Option<&str>, limit: usize) -> Result<(), String> {
    let path = std::env::var("UTLD_DECISION_EVENTS")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());

    let file = File::open(&path)
        .map_err(|e| format!("failed to open decision events {}: {}", path, e))?;
    let reader = std::io::BufReader::new(file);

    let mut printed = 0usize;
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("failed to read line from {}: {}", path, e);
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let ev: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("failed to parse decision event JSON: {}", e);
                continue;
            }
        };

        if let Some(filter) = snark_status {
            let status = ev
                .get("snark_high_threat_merkle_status")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if status != filter {
                continue;
            }
        }

        println!("{}", line);
        printed += 1;
        if printed >= limit {
            break;
        }
    }

    Ok(())
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

fn cmd_truth_snapshot(
    client: &UtlClient,
    entity_id: u128,
    root_id: u128,
) -> Result<(), String> {
    let index_path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let index_head_path = format!("{}.head", index_path);
    let dig_index_head = std::fs::read_to_string(&index_head_path)
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let ledger_path = policy_ledger_path();
    let ledger_head_path = format!("{}.head", ledger_path);
    let policy_ledger_head = std::fs::read_to_string(&ledger_head_path)
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let payload = SnapshotPayload {
        kind: "truth_snapshot",
        dig_index_head: &dig_index_head,
        policy_ledger_head: &policy_ledger_head,
    };

    let data = serde_json::to_vec(&payload)
        .map_err(|e| format!("failed to serialize snapshot payload: {}", e))?;

    let addr_heap_hash = [0u8; 32];
    let hook_hash = [0u8; 32];

    let mut signature: Vec<u8> = Vec::new();
    if let Ok(key_hex) = std::env::var("UTLD_SIG_KEY") {
        let key_bytes = hex::decode(&key_hex)
            .map_err(|e| format!("invalid UTLD_SIG_KEY hex: {}", e))?;

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&key_bytes)
            .map_err(|_| "failed to create HMAC from UTLD_SIG_KEY".to_string())?;

        let mut buf = Vec::new();
        buf.extend_from_slice(&entity_id.to_le_bytes());
        buf.extend_from_slice(&root_id.to_le_bytes());
        buf.extend_from_slice(&addr_heap_hash);
        buf.extend_from_slice(&hook_hash);
        buf.extend_from_slice(&data);

        mac.update(&buf);
        let sig = mac.finalize().into_bytes();
        signature = sig.to_vec();
    }

    let mut p_container = BTreeMap::new();
    p_container.insert("event_kind".to_string(), "truth_snapshot".to_string());
    p_container.insert("dig_index_head".to_string(), dig_index_head);
    p_container.insert("policy_ledger_head".to_string(), policy_ledger_head);

    let req = NodeRequest::RecordTransition {
        entity_id,
        root_id,
        signature,
        data,
        addr_heap_hash,
        p_container,
        logic_ref: "truth_snapshot".to_string(),
        wall: "snapshot".to_string(),
        hook_hash,
    };

    match client.send(&req).map_err(err_to_string)? {
        NodeResponse::Ok => {
            println!("truth snapshot recorded for root {}", root_id);
            Ok(())
        }
        other => Err(format!("unexpected response: {:?}", other)),
    }
}

fn cmd_truth_snapshot_list(limit: usize) -> Result<(), String> {
    let path = std::env::var("UTLD_DECISION_EVENTS")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            println!("no decision events file {}: {}", path, e);
            return Ok(());
        }
    };
    let reader = std::io::BufReader::new(file);

    let mut printed = 0usize;
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("failed to read line from {}: {}", path, e);
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let ev: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("failed to parse decision event JSON: {}", e);
                continue;
            }
        };

        let kind = ev
            .get("event_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if kind != "truth_snapshot" {
            continue;
        }

        println!("{}", line);
        printed += 1;
        if printed >= limit {
            break;
        }
    }

    if printed == 0 {
        println!("no truth_snapshot events found in {}", path);
    }

    Ok(())
}

fn compute_linked_hash(prev: Option<&str>, line: &[u8]) -> String {
    let mut data = Vec::new();
    if let Some(p) = prev {
        data.extend_from_slice(p.as_bytes());
    }
    data.extend_from_slice(line);

    let hash = hash_bytes(&data);
    let mut s = String::with_capacity(64);
    for b in &hash.0 {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn compute_chain_head_from_file(path: &str) -> Result<String, String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            return Err(format!("failed to open {}: {}", path, e));
        }
    };
    let reader = std::io::BufReader::new(file);

    let mut prev: Option<String> = None;
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("failed to read line from {}: {}", path, e);
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let h = compute_linked_hash(prev.as_deref(), trimmed.as_bytes());
        prev = Some(h);
    }

    Ok(prev.unwrap_or_default())
}

fn cmd_truth_snapshot_verify() -> Result<(), String> {
    // Verify dig index chain head.
    let idx_path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let idx_head_path = format!("{}.head", idx_path);
    let idx_head_file = std::fs::read_to_string(&idx_head_path)
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let idx_computed = compute_chain_head_from_file(&idx_path)?;

    let idx_status = if idx_computed == idx_head_file && !idx_computed.is_empty() {
        "ok"
    } else {
        "mismatch"
    };

    println!(
        "dig_index_head: computed={} head_file={} status={}",
        idx_computed,
        idx_head_file,
        idx_status,
    );

    // Verify policy ledger chain head.
    let ledger_path = policy_ledger_path();
    let ledger_head_path = format!("{}.head", ledger_path);
    let ledger_head_file = std::fs::read_to_string(&ledger_head_path)
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let ledger_computed = compute_chain_head_from_file(&ledger_path)?;

    let ledger_status = if ledger_computed == ledger_head_file && !ledger_computed.is_empty() {
        "ok"
    } else {
        "mismatch"
    };

    println!(
        "policy_ledger_head: computed={} head_file={} status={}",
        ledger_computed,
        ledger_head_file,
        ledger_status,
    );

    Ok(())
}

fn cmd_truth_snapshot_export() -> Result<(), String> {
    // Reuse the same head computation used by verify.
    let idx_path = std::env::var("UTLD_DIG_INDEX").unwrap_or_else(|_| "./dig_index.jsonl".to_string());
    let idx_head = compute_chain_head_from_file(&idx_path)?;

    let ledger_path = policy_ledger_path();
    let ledger_head = compute_chain_head_from_file(&ledger_path)?;

    #[derive(serde::Serialize)]
    struct ExportSnapshot<'a> {
        kind: &'a str,
        dig_index_path: &'a str,
        dig_index_head: &'a str,
        policy_ledger_path: &'a str,
        policy_ledger_head: &'a str,
        ts: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        witness_sig_hex: Option<String>,
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut snapshot = ExportSnapshot {
        kind: "truth_snapshot_export",
        dig_index_path: &idx_path,
        dig_index_head: &idx_head,
        policy_ledger_path: &ledger_path,
        policy_ledger_head: &ledger_head,
        ts: now,
        witness_sig_hex: None,
    };

    // Optional witness signing using UTLD_WITNESS_SIG_KEY (hex HMAC-SHA256 over JSON body).
    if let Ok(key_hex) = std::env::var("UTLD_WITNESS_SIG_KEY") {
        if let Ok(key_bytes) = hex::decode(&key_hex) {
            if let Ok(body) = serde_json::to_vec(&snapshot) {
                type HmacSha256 = Hmac<Sha256>;
                if let Ok(mut mac) = HmacSha256::new_from_slice(&key_bytes) {
                    mac.update(&body);
                    let sig = mac.finalize().into_bytes();
                    snapshot.witness_sig_hex = Some(hex::encode(sig));
                } else {
                    eprintln!("failed to create HMAC from UTLD_WITNESS_SIG_KEY; skipping witness signature");
                }
            }
        } else {
            eprintln!("UTLD_WITNESS_SIG_KEY is not valid hex; skipping witness signature");
        }
    }

    let json = serde_json::to_string_pretty(&snapshot)
        .map_err(|e| format!("failed to serialize export snapshot: {}", e))?;
    println!("{}", json);

    Ok(())
}

fn cmd_lawbook_ledger_check(path: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read lawbook file {}: {}", path, e))?;

    let lb: Lawbook = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse lawbook file {}: {}", path, e))?;

    validate_lawbook(&lb)?;

    let ledger_path = policy_ledger_path();
    let file = std::fs::File::open(&ledger_path)
        .map_err(|e| format!("failed to open policy ledger {}: {}", ledger_path, e))?;

    let reader = std::io::BufReader::new(file);
    let mut any_for_policy = false;
    let mut found_exact = None;
    let mut latest_version: Option<u64> = None;
    let mut latest_ts: Option<u64> = None;

    for line_result in reader.lines() {
        let line = line_result
            .map_err(|e| format!("error reading policy ledger {}: {}", ledger_path, e))?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: PolicyLedgerEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping malformed policy ledger entry: {}", e);
                continue;
            }
        };

        if entry.policy_id.as_str() != lb.policy_id {
            continue;
        }

        any_for_policy = true;

        if entry.version == lb.version {
            found_exact = Some(entry.ts);
        }

        match latest_version {
            Some(v) if entry.version > v => {
                latest_version = Some(entry.version);
                latest_ts = Some(entry.ts);
            }
            None => {
                latest_version = Some(entry.version);
                latest_ts = Some(entry.ts);
            }
            _ => {}
        }
    }

    if let Some(ts) = found_exact {
        println!(
            "lawbook ledger check ok: tenant_id={} policy_id={} version={} ts={}",
            lb.tenant_id,
            lb.policy_id,
            lb.version,
            ts,
        );
        return Ok(());
    }

    if !any_for_policy {
        return Err(format!(
            "no policy ledger entries found for policy_id={} (lawbook tenant_id={} version={})",
            lb.policy_id,
            lb.tenant_id,
            lb.version,
        ));
    }

    let latest_v = latest_version.unwrap_or(0);
    let latest_ts = latest_ts.unwrap_or(0);

    Err(format!(
        "no policy ledger entry for policy_id={} version={} (latest in ledger is version={} ts={})",
        lb.policy_id,
        lb.version,
        latest_v,
        latest_ts,
    ))
}

#[derive(serde::Serialize)]
struct SnapshotPayload<'a> {
    kind: &'a str,
    dig_index_head: &'a str,
    policy_ledger_head: &'a str,
}

#[derive(serde::Deserialize)]
struct PolicyLedgerEntry {
    ts: u64,
    policy_id: String,
    version: u64,
    policy_hash_hex: String,
    cue_hash_hex: Option<String>,
    issuer: Option<String>,
    #[serde(rename = "signature_hex")]
    _signature_hex: Option<String>,
    #[serde(rename = "meta")]
    _meta: BTreeMap<String, String>,
    #[serde(default)]
    prev_entry_hash: Option<String>,
}

fn policy_ledger_path() -> String {
    std::env::var("UTLD_POLICY_LEDGER").unwrap_or_else(|_| "./policy_ledger.jsonl".to_string())
}

fn cmd_policy_ledger_list(policy_id: Option<&str>, limit: usize) -> Result<(), String> {
    let path = policy_ledger_path();
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("failed to open policy ledger {}: {}", path, e))?;

    let reader = std::io::BufReader::new(file);
    let mut printed = 0usize;

    for line_result in reader.lines() {
        let line = line_result
            .map_err(|e| format!("error reading policy ledger {}: {}", path, e))?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: PolicyLedgerEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping malformed policy ledger entry: {}", e);
                continue;
            }
        };

        if let Some(pid) = policy_id {
            if entry.policy_id.as_str() != pid {
                continue;
            }
        }

        let cue = entry.cue_hash_hex.as_deref().unwrap_or("");
        let issuer = entry.issuer.as_deref().unwrap_or("");
        let prev = entry.prev_entry_hash.as_deref().unwrap_or("");

        println!(
            "ts={} policy_id={} version={} hash={} cue_hash={} issuer={} prev={}",
            entry.ts,
            entry.policy_id,
            entry.version,
            entry.policy_hash_hex,
            cue,
            issuer,
            prev,
        );

        printed += 1;
        if printed >= limit {
            break;
        }
    }

    if printed == 0 {
        println!("no policy ledger entries matched the filters");
    }

    Ok(())
}

fn cmd_policy_burn(
    client: &UtlClient,
    policy_id: &str,
    version: u64,
    policy_file: &str,
    cue_hash: Option<&str>,
    issuer: Option<&str>,
) -> Result<(), String> {
    if policy_id.trim().is_empty() {
        return Err("policy_id must be non-empty".to_string());
    }
    if version == 0 {
        return Err("policy version must be > 0".to_string());
    }

    let content = std::fs::read_to_string(policy_file)
        .map_err(|e| format!("failed to read policy file {}: {}", policy_file, e))?;

    let hash = hash_bytes(content.as_bytes());
    let policy_hash_hex = hex::encode(hash.0);

    let cue_hash_hex = cue_hash.map(|s| s.to_string());
    let issuer_str = issuer.map(|s| s.to_string());

    let mut signature_hex: Option<String> = None;
    if let Ok(key_hex) = std::env::var("UTLD_POLICY_BURN_KEY") {
        let key_bytes = hex::decode(&key_hex)
            .map_err(|e| format!("invalid UTLD_POLICY_BURN_KEY hex: {}", e))?;

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&key_bytes)
            .map_err(|_| "failed to create HMAC from UTLD_POLICY_BURN_KEY".to_string())?;

        let cue = cue_hash_hex.clone().unwrap_or_default();
        let canonical = format!(
            "{}:{}:{}:{}",
            policy_id, version, policy_hash_hex, cue
        );
        mac.update(canonical.as_bytes());
        let sig = mac.finalize().into_bytes();
        signature_hex = Some(hex::encode(sig));
    }

    let mut meta = BTreeMap::new();
    meta.insert("policy_file".to_string(), policy_file.to_string());

    let req = PolicyBurnRequest {
        policy_id: policy_id.to_string(),
        version,
        policy_hash_hex,
        cue_hash_hex,
        issuer: issuer_str,
        signature_hex,
        meta,
    };

    let node_req = NodeRequest::PolicyBurn { request: req };

    match client.send(&node_req).map_err(err_to_string)? {
        NodeResponse::Ok => {
            println!("policy burn recorded: {} v{}", policy_id, version);
            Ok(())
        }
        other => Err(format!("unexpected response: {:?}", other)),
    }
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

fn cmd_dig_snark_inclusion(
    file_id: &str,
    root_id: Option<&str>,
    index: usize,
) -> Result<(), String> {
    use zk_snark::{self, build_snark_merkle_path_from_hashes, hash_to_fr, fr_to_hex,
        setup_merkle_inclusion, prove_merkle_inclusion, verify_merkle_inclusion};

    // Locate the dig index entry.
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

    let snark_root_hex = entry.snark_root.as_deref().ok_or_else(|| {
        format!(
            "snark_root not present in dig index for file_id={} root_id={}",
            entry.file_id, entry.root_id,
        )
    })?;

    // Resolve DigFile path similar to cmd_dig_inspect_id.
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

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read dig file {}: {}", path, e))?;
    let dig: DigFile = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse dig file {}: {}", path, e))?;

    if index >= dig.dig_records.len() {
        return Err(format!(
            "record index {} out of bounds for dig file (records={})",
            index,
            dig.dig_records.len(),
        ));
    }

    // Rebuild leaves and Merkle path.
    let leaves: Vec<Hash> = dig.dig_records.iter().map(|r| r.leaf_hash()).collect();
    let (root_fr, leaf_fr, siblings, is_left) =
        build_snark_merkle_path_from_hashes(&leaves, index)
            .ok_or_else(|| "failed to build Merkle path".to_string())?;

    // Optional consistency check against stored snark_root.
    let computed_root_hex = fr_to_hex(&root_fr);
    if computed_root_hex != snark_root_hex {
        return Err(format!(
            "snark_root mismatch: index has {} but computed {}",
            snark_root_hex,
            computed_root_hex,
        ));
    }

    let depth = siblings.len();
    let circuit_id = UID::new();
    let keys = setup_merkle_inclusion(circuit_id, depth)
        .map_err(|e| format!("setup_merkle_inclusion failed: {:?}", e))?;

    let (proof, root_again) = prove_merkle_inclusion(&keys, leaf_fr, &siblings, &is_left)
        .map_err(|e| format!("prove_merkle_inclusion failed: {:?}", e))?;

    if root_again != root_fr {
        return Err("internal error: proof root does not match computed root".to_string());
    }

    let ok = verify_merkle_inclusion(&keys, &proof, root_fr, leaf_fr)
        .map_err(|e| format!("verify_merkle_inclusion failed: {:?}", e))?;

    if !ok {
        return Err("merkle inclusion proof did not verify".to_string());
    }

    println!(
        "dig_snark_inclusion_ok: file_id={} root_id={} index={} snark_root={}",
        entry.file_id,
        entry.root_id,
        index,
        snark_root_hex,
    );

    Ok(())
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
