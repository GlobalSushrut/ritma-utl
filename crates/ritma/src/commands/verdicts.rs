use anyhow::Result;
use colored::*;

pub async fn run(namespace: String, limit: usize) -> Result<()> {
    println!(
        "{}",
        format!("⚖️  Recent verdicts for {namespace}")
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        format!("Showing last {limit} verdicts").bright_white()
    );
    println!();
    println!("{}", "(Connect to IndexDB to show real verdicts)".yellow());
    Ok(())
}
