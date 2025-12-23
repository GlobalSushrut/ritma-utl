//! Ritma - Universal Truth Layer CLI
//!
//! The unified command-line interface for Ritma governance.

use clap::{Parser, Subcommand};

mod commands;
mod demo;

#[derive(Parser)]
#[command(name = "ritma")]
#[command(version, about = "Universal Truth Layer - Security Governance Made Simple", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the hello-world demo (5-minute quickstart)
    Demo {
        /// Port to run demo server on
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },

    /// Initialize a new Ritma namespace
    Init {
        /// Namespace ID (e.g., ns://acme/prod/api/svc)
        namespace: String,
    },

    /// Show events for a namespace
    Events {
        /// Namespace ID
        namespace: String,

        /// Number of recent events to show
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Show verdicts for a namespace
    Verdicts {
        /// Namespace ID
        namespace: String,

        /// Number of recent verdicts to show
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Show intent baseline and drift
    Intent {
        /// Namespace ID
        namespace: String,
    },

    /// Generate and verify proofs
    Proof {
        #[command(subcommand)]
        action: ProofAction,
    },

    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Show system status
    Status,
}

#[derive(Subcommand)]
enum ProofAction {
    /// Generate a proof
    Generate {
        /// Proof type (receipt-chain or verdict-attestation)
        #[arg(short, long)]
        proof_type: String,

        /// Namespace ID
        namespace: String,
    },

    /// Verify a proof
    Verify {
        /// Proof ID
        proof_id: String,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show {
        /// Namespace ID
        namespace: String,
    },

    /// Update configuration
    Update {
        /// Namespace ID
        namespace: String,

        /// Config file path
        #[arg(short, long)]
        file: String,
    },

    /// Show configuration diff
    Diff {
        /// Namespace ID
        namespace: String,

        /// From config hash
        from: String,

        /// To config hash
        to: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Demo { port } => {
            demo::run_demo(port).await?;
        }
        Commands::Init { namespace } => {
            commands::init::run(namespace).await?;
        }
        Commands::Events { namespace, limit } => {
            commands::events::run(namespace, limit).await?;
        }
        Commands::Verdicts { namespace, limit } => {
            commands::verdicts::run(namespace, limit).await?;
        }
        Commands::Intent { namespace } => {
            commands::intent::run(namespace).await?;
        }
        Commands::Proof { action } => {
            commands::proof::run(action).await?;
        }
        Commands::Config { action } => {
            commands::config::run(action).await?;
        }
        Commands::Status => {
            commands::status::run().await?;
        }
    }

    Ok(())
}
