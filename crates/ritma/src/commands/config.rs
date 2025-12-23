use crate::ConfigAction;
use anyhow::Result;
use colored::*;

pub async fn run(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show { namespace } => {
            println!(
                "{}",
                format!("⚙️  Configuration for {namespace}")
                    .bright_cyan()
                    .bold()
            );
            println!("{}", "(Connect to bar_config to show)".yellow());
        }
        ConfigAction::Update { namespace, file } => {
            println!(
                "{}",
                format!("📝 Updating config for {namespace} from {file}")
                    .bright_cyan()
                    .bold()
            );
            println!("{}", "(Connect to bar_config to update)".yellow());
        }
        ConfigAction::Diff {
            namespace,
            from,
            to,
        } => {
            println!(
                "{}",
                format!("🔄 Config diff for {namespace}")
                    .bright_cyan()
                    .bold()
            );
            println!("{}", format!("From: {from} → To: {to}").bright_white());
            println!("{}", "(Connect to bar_config to diff)".yellow());
        }
    }
    Ok(())
}
