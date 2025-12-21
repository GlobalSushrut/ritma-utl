use std::fs;

use clap::{Parser, Subcommand};
use policy_store::{
    append_commit, append_tag, compute_commit_id, compute_policy_tree_hash, now_ts, read_commits,
    read_tags, PolicyCommit, PolicyTag,
};

#[derive(Parser)]
#[command(name = "utl-policy", about = "UTL policy commit and tag tool", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new policy commit from a policy file.
    Commit {
        /// Author string (e.g. email or name).
        #[arg(long)]
        author: String,
        /// Commit message.
        #[arg(long)]
        message: String,
        /// Path to policy file (JSON TruthScript IR).
        #[arg(long)]
        file: String,
        /// Optional parent commit id.
        #[arg(long)]
        parent: Option<String>,
    },
    /// List recent policy commits.
    Log {
        /// Maximum number of commits to print.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Tag a policy commit (e.g. soc2-2025-audit).
    Tag {
        /// Tag name.
        #[arg(long)]
        tag: String,
        /// Target commit id.
        #[arg(long)]
        commit: String,
        /// Optional framework label (e.g. SOC2, PCI, HIPAA).
        #[arg(long)]
        framework: Option<String>,
        /// Who is creating the tag.
        #[arg(long)]
        created_by: String,
        /// Optional free-form notes.
        #[arg(long)]
        notes: Option<String>,
    },
    /// List policy tags.
    Tags {
        /// Maximum number of tags to print.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Commit {
            author,
            message,
            file,
            parent,
        } => cmd_commit(&author, &message, &file, parent.as_deref()),
        Commands::Log { limit } => cmd_log(limit),
        Commands::Tag {
            tag,
            commit,
            framework,
            created_by,
            notes,
        } => cmd_tag(&tag, &commit, framework.as_deref(), &created_by, notes.as_deref()),
        Commands::Tags { limit } => cmd_tags(limit),
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_commit(author: &str, message: &str, file: &str, parent: Option<&str>) -> Result<(), String> {
    let bytes = fs::read(file).map_err(|e| format!("failed to read policy file {}: {}", file, e))?;
    let policy_tree_hash = compute_policy_tree_hash(&bytes);
    let ts = now_ts();
    let commit_id = compute_commit_id(parent, author, message, &policy_tree_hash, ts);

    let commit = PolicyCommit {
        commit_id,
        parent: parent.map(|s| s.to_string()),
        author: author.to_string(),
        timestamp: ts,
        message: message.to_string(),
        policy_tree_hash,
    };

    append_commit(&commit)?;
    println!("{}", commit.commit_id);
    Ok(())
}

fn cmd_log(limit: usize) -> Result<(), String> {
    let mut commits = read_commits()?;
    commits.reverse();
    for c in commits.into_iter().take(limit) {
        println!("{} {} {}", c.commit_id, c.timestamp, c.message);
    }
    Ok(())
}

fn cmd_tag(
    tag: &str,
    commit: &str,
    framework: Option<&str>,
    created_by: &str,
    notes: Option<&str>,
) -> Result<(), String> {
    let ts = now_ts();
    let tag_obj = PolicyTag {
        tag: tag.to_string(),
        commit_id: commit.to_string(),
        framework: framework.map(|s| s.to_string()),
        created_by: created_by.to_string(),
        created_at: ts,
        notes: notes.map(|s| s.to_string()),
    };

    append_tag(&tag_obj)?;
    println!("{} -> {}", tag_obj.tag, tag_obj.commit_id);
    Ok(())
}

fn cmd_tags(limit: usize) -> Result<(), String> {
    let mut tags = read_tags()?;
    tags.reverse();
    for t in tags.into_iter().take(limit) {
        println!("{} {} {}", t.tag, t.commit_id, t.framework.unwrap_or_default());
    }
    Ok(())
}
