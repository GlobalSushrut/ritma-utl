use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ritma-lab")]
#[command(about = "Ritma Lab - Production-grade demo environment")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Use real Ritma (production-grade evidence chain)
    #[arg(long, global = true)]
    pub real_ritma: bool,

    /// Lab directory
    #[arg(long, global = true, default_value = ".")]
    pub lab_dir: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new lab directory
    Init {
        #[arg(short, long, default_value = ".")]
        path: String,
    },

    /// Start the lab
    Up {
        #[arg(short, long)]
        topology: Option<String>,

        #[arg(short, long)]
        scenario: Option<String>,
    },

    /// Stop the lab
    Down {
        #[arg(short, long)]
        force: bool,
    },

    /// Show lab status
    Status,

    /// Export proofpack
    Export {
        #[arg(short, long, default_value = "./output")]
        output: String,

        #[arg(short, long)]
        last: Option<String>,
    },

    /// Verify a proofpack
    Verify {
        path: String,
    },

    /// Run a scenario
    Run {
        #[arg(short, long)]
        scenario: String,

        #[arg(short, long)]
        topology: Option<String>,
    },
}
