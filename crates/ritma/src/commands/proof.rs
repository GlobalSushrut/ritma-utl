use crate::ProofAction;
use anyhow::Result;
use colored::*;

pub async fn run(action: ProofAction) -> Result<()> {
    match action {
        ProofAction::Generate {
            proof_type,
            namespace,
        } => {
            println!(
                "{}",
                format!("🔐 Generating {proof_type} proof for {namespace}")
                    .bright_cyan()
                    .bold()
            );
            println!("{}", "(Connect to proof_standards to generate)".yellow());
        }
        ProofAction::Verify { proof_id } => {
            println!(
                "{}",
                format!("✅ Verifying proof {proof_id}")
                    .bright_cyan()
                    .bold()
            );
            println!("{}", "(Connect to proof_standards to verify)".yellow());
        }
    }
    Ok(())
}
