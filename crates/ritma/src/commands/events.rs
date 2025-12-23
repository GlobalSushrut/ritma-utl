use anyhow::Result;
use colored::*;

pub async fn run(namespace: String, limit: usize) -> Result<()> {
    println!(
        "{}",
        format!("📊 Recent events for {namespace}")
            .bright_cyan()
            .bold()
    );
    println!("{}", format!("Showing last {limit} events").bright_white());
    println!();
    println!("{}", "(Connect to IndexDB to show real events)".yellow());
    Ok(())
}
