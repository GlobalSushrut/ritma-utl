use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use clap::{Parser, Subcommand};
use serde_json::Value as JsonValue;
use tenant_policy::Lawbook;
use truthscript::Policy as TsPolicy;

#[derive(Parser)]
#[command(
    name = "utl_cue",
    about = "CUE tooling for Ritma / UTL policies",
    version
)]
struct Cli {
    /// Override CUE binary name or path (defaults to `cue`).
    #[arg(long)]
    cue_bin: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a TruthScript policy JSON from a CUE file.
    PolicyBuild {
        /// Path to CUE file defining a Policy value.
        #[arg(long)]
        file: String,
        /// Optional output path for JSON (stdout if omitted).
        #[arg(long)]
        out: Option<String>,
    },

    /// Build a tenant lawbook JSON from a CUE file.
    LawbookBuild {
        /// Path to CUE file defining a Lawbook value.
        #[arg(long)]
        file: String,
        /// Optional output path for JSON (stdout if omitted).
        #[arg(long)]
        out: Option<String>,
    },
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let cue_bin = cli.cue_bin.unwrap_or_else(|| "cue".to_string());

    match cli.command {
        Commands::PolicyBuild { file, out } => {
            let json = build_policy_json(&cue_bin, &file)?;
            write_output(&json, out.as_deref())?;
            Ok(())
        }
        Commands::LawbookBuild { file, out } => {
            let json = build_lawbook_json(&cue_bin, &file)?;
            write_output(&json, out.as_deref())?;
            Ok(())
        }
    }
}

fn build_policy_json(cue_bin: &str, file: &str) -> Result<String, String> {
    let raw = run_cue_export(cue_bin, file)?;

    let value: JsonValue = serde_json::from_str(&raw)
        .map_err(|e| format!("cue export did not produce valid JSON: {e}"))?;

    let policy: TsPolicy = serde_json::from_value(value)
        .map_err(|e| format!("failed to parse TruthScript Policy from JSON: {e}"))?;

    serde_json::to_string_pretty(&policy)
        .map_err(|e| format!("failed to serialize Policy JSON: {e}"))
}

fn build_lawbook_json(cue_bin: &str, file: &str) -> Result<String, String> {
    let raw = run_cue_export(cue_bin, file)?;

    let value: JsonValue = serde_json::from_str(&raw)
        .map_err(|e| format!("cue export did not produce valid JSON: {e}"))?;

    let lawbook: Lawbook = serde_json::from_value(value)
        .map_err(|e| format!("failed to parse Lawbook from JSON: {e}"))?;

    serde_json::to_string_pretty(&lawbook)
        .map_err(|e| format!("failed to serialize Lawbook JSON: {e}"))
}

fn run_cue_export(cue_bin: &str, file: &str) -> Result<String, String> {
    if !Path::new(file).exists() {
        return Err(format!("CUE file not found: {file}"));
    }

    let output = Command::new(cue_bin)
        .arg("export")
        .arg(file)
        .output()
        .map_err(|e| format!("failed to invoke '{cue_bin}': {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        return Err(format!("cue export failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

    // Basic sanity check: ensure it looks like JSON (starts with { or [).
    let trimmed = stdout.trim_start();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return Err("cue export did not produce JSON".to_string());
    }

    Ok(stdout)
}

fn write_output(json: &str, out: Option<&str>) -> Result<(), String> {
    match out {
        Some(path) => {
            let mut file = File::create(path)
                .map_err(|e| format!("failed to create output file {path}: {e}"))?;
            file.write_all(json.as_bytes())
                .map_err(|e| format!("failed to write JSON to {path}: {e}"))?;
            Ok(())
        }
        None => {
            let mut stdout = std::io::stdout();
            stdout
                .write_all(json.as_bytes())
                .map_err(|e| format!("failed to write JSON to stdout: {e}"))?;
            Ok(())
        }
    }
}
