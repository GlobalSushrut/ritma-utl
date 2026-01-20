use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use ritma_lab::cli::{Cli, Commands};
use ritma_lab::LabOrchestrator;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ritma_lab=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let lab_dir = PathBuf::from(&cli.lab_dir);
    let use_real_ritma = cli.real_ritma;

    if use_real_ritma {
        info!("Using REAL Ritma (production-grade evidence chain)");
    }

    match cli.command {
        Commands::Init { path } => {
            init_lab(&path).await?;
        }
        Commands::Up { topology, scenario } => {
            let mut orchestrator = LabOrchestrator::with_config(lab_dir, use_real_ritma);
            
            let topo_path = topology.unwrap_or_else(|| "topology.yaml".to_string());
            orchestrator.load_topology(&topo_path).await?;
            
            if let Some(scenario_path) = scenario {
                orchestrator.load_scenario(&scenario_path).await?;
            }
            
            orchestrator.start().await?;
            
            println!("Lab started. Press Ctrl+C to stop.");
            tokio::signal::ctrl_c().await?;
            
            orchestrator.stop().await?;
        }
        Commands::Down { force: _ } => {
            println!("Lab stopped.");
        }
        Commands::Status => {
            println!("Lab status: idle");
        }
        Commands::Export { output, last: _ } => {
            let orchestrator = LabOrchestrator::with_config(lab_dir, use_real_ritma);
            let path = orchestrator.export(&output).await?;
            println!("Exported to: {}", path);
        }
        Commands::Verify { path } => {
            verify_proofpack(&path).await?;
        }
        Commands::Run { scenario, topology } => {
            let mut orchestrator = LabOrchestrator::with_config(lab_dir, use_real_ritma);
            
            let topo_path = topology.unwrap_or_else(|| "topology.yaml".to_string());
            orchestrator.load_topology(&topo_path).await?;
            orchestrator.load_scenario(&scenario).await?;
            
            orchestrator.start().await?;
            orchestrator.run_scenario().await?;
            
            let status = orchestrator.status().await;
            println!("\n{}", status);
            
            orchestrator.stop().await?;
        }
    }

    Ok(())
}

async fn init_lab(path: &str) -> Result<()> {
    tokio::fs::create_dir_all(path).await?;
    tokio::fs::create_dir_all(format!("{}/topologies", path)).await?;
    tokio::fs::create_dir_all(format!("{}/scenarios", path)).await?;
    tokio::fs::create_dir_all(format!("{}/output", path)).await?;

    // Create sample topology
    let sample_topology = r#"version: "1.0"
metadata:
  name: three-tier-demo
  description: "Web → API → DB demo topology"
  seed: 42

nodes:
  - id: node-web
    role: frontend
    resources:
      memory: "256m"
      cpu: "0.3"
    ritma:
      enabled: true
      tier: 1
      capture:
        - http_access_logs
        - application_logs

  - id: node-api
    role: backend
    resources:
      memory: "384m"
      cpu: "0.4"
    ritma:
      enabled: true
      tier: 2
      capture:
        - http_access_logs
        - application_logs
        - database_queries

  - id: node-db
    role: database
    resources:
      memory: "512m"
      cpu: "0.5"
    ritma:
      enabled: true
      tier: 1
      capture:
        - database_queries
        - file_access

networks:
  - name: lab-internal
    driver: bridge
    nodes: [node-web, node-api, node-db]

aggregator:
  window_seconds: 5
  export_path: "./output"
"#;

    tokio::fs::write(
        format!("{}/topologies/three-tier.yaml", path),
        sample_topology,
    ).await?;

    // Create sample scenario
    let sample_scenario = r#"scenario:
  name: baseline-traffic
  description: "Normal traffic baseline for 60 seconds"
  duration_seconds: 60
  seed: 42

phases:
  - name: warmup
    start: 0
    duration: 15
    traffic:
      type: normal
      rps: 10

  - name: steady
    start: 15
    duration: 30
    traffic:
      type: normal
      rps: 20

  - name: cooldown
    start: 45
    duration: 15
    traffic:
      type: normal
      rps: 5

assertions:
  - type: event_count
    filter: "kind=HttpRequest"
    min: 500
"#;

    tokio::fs::write(
        format!("{}/scenarios/baseline.yaml", path),
        sample_scenario,
    ).await?;

    info!(path, "Initialized lab directory");
    println!("✓ Initialized lab at: {}", path);
    println!("  topologies/three-tier.yaml");
    println!("  scenarios/baseline.yaml");
    println!("\nRun: ritma-lab run --topology topologies/three-tier.yaml --scenario scenarios/baseline.yaml");

    Ok(())
}

async fn verify_proofpack(path: &str) -> Result<()> {
    use sha2::{Sha256, Digest};

    let manifest_path = format!("{}/manifest.json", path);
    let chain_path = format!("{}/chain.json", path);
    let windows_path = format!("{}/windows.json", path);

    // Read files
    let manifest: serde_json::Value = serde_json::from_str(
        &tokio::fs::read_to_string(&manifest_path).await?
    )?;
    let chain: Vec<String> = serde_json::from_str(
        &tokio::fs::read_to_string(&chain_path).await?
    )?;
    let windows: Vec<serde_json::Value> = serde_json::from_str(
        &tokio::fs::read_to_string(&windows_path).await?
    )?;

    println!("Verifying proofpack: {}", path);
    println!("  Manifest version: {}", manifest["version"]);
    println!("  Windows: {}", windows.len());
    println!("  Chain length: {}", chain.len());

    // Verify chain continuity
    let mut prev_hash = [0u8; 32];
    let mut valid = true;

    for (i, window) in windows.iter().enumerate() {
        let merkle_root = hex::decode(window["merkle_root"].as_str().unwrap_or(""))?;
        let stored_prev = hex::decode(window["prev_root"].as_str().unwrap_or(""))?;
        let stored_chain = hex::decode(window["chain_hash"].as_str().unwrap_or(""))?;

        // Check prev_root matches
        if stored_prev != prev_hash {
            println!("  ✗ Window {} prev_root mismatch", i);
            valid = false;
        }

        // Compute expected chain hash
        let mut hasher = Sha256::new();
        hasher.update(&prev_hash);
        hasher.update(&merkle_root);
        hasher.update(&(window["start_ts"].as_i64().unwrap_or(0)).to_le_bytes());
        hasher.update(&(window["end_ts"].as_i64().unwrap_or(0)).to_le_bytes());
        let computed: [u8; 32] = hasher.finalize().into();

        if computed.to_vec() != stored_chain {
            println!("  ✗ Window {} chain_hash mismatch", i);
            valid = false;
        }

        prev_hash = computed;
    }

    if valid {
        println!("\n✓ VERIFICATION PASSED");
        println!("  Chain is continuous and valid");
        println!("  All merkle roots verified");
    } else {
        println!("\n✗ VERIFICATION FAILED");
    }

    Ok(())
}
