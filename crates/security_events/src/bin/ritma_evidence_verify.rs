// Evidence verification tool for Ritma
// Verifies hash chain integrity of decision events and compliance records

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process;
use security_events::DecisionEvent;
use sha2::{Sha256, Digest};

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: ritma-evidence-verify <log_file.jsonl>");
        eprintln!();
        eprintln!("Verifies hash chain integrity of evidence logs:");
        eprintln!("  - Checks that each record's prev_hash matches previous record_hash");
        eprintln!("  - Recomputes and verifies record_hash for each entry");
        eprintln!("  - Reports any breaks in the chain");
        process::exit(1);
    }

    let log_path = &args[1];
    
    println!("Verifying evidence log: {}", log_path);
    println!();

    let file = match File::open(log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Error opening file: {}", e);
            process::exit(1);
        }
    };

    let reader = BufReader::new(file);
    let mut prev_hash: Option<String> = None;
    let mut line_num = 0;
    let mut total_records = 0;
    let mut errors = 0;
    let mut warnings = 0;

    for line_result in reader.lines() {
        line_num += 1;
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("❌ Error reading line {}: {}", line_num, e);
                errors += 1;
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        // Parse record
        let event: DecisionEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("❌ Line {}: Invalid JSON: {}", line_num, e);
                errors += 1;
                continue;
            }
        };

        total_records += 1;

        // Check 1: Schema version
        if event.schema_version == 0 {
            eprintln!("⚠️  Line {}: No schema_version (legacy record)", line_num);
            warnings += 1;
        }

        // Check 2: prev_hash linkage
        if total_records > 1 {
            match (&prev_hash, &event.prev_hash) {
                (Some(expected), Some(actual)) => {
                    if expected != actual {
                        eprintln!("❌ Line {}: Hash chain broken!", line_num);
                        eprintln!("   Expected prev_hash: {}", expected);
                        eprintln!("   Actual prev_hash:   {}", actual);
                        errors += 1;
                    }
                }
                (Some(_), None) => {
                    eprintln!("⚠️  Line {}: Missing prev_hash (chain break)", line_num);
                    warnings += 1;
                }
                (None, Some(_)) => {
                    eprintln!("⚠️  Line {}: Has prev_hash but previous record had none", line_num);
                    warnings += 1;
                }
                (None, None) => {
                    // Both missing, legacy records
                }
            }
        } else {
            // First record
            if event.prev_hash.is_some() {
                eprintln!("⚠️  Line {}: First record has prev_hash (should be None)", line_num);
                warnings += 1;
            }
        }

        // Check 3: Verify record_hash
        if let Some(stored_hash) = &event.record_hash {
            let computed_hash = match compute_event_hash(&event) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("❌ Line {}: Error computing hash: {}", line_num, e);
                    errors += 1;
                    continue;
                }
            };

            if &computed_hash != stored_hash {
                eprintln!("❌ Line {}: Record hash mismatch!", line_num);
                eprintln!("   Stored:   {}", stored_hash);
                eprintln!("   Computed: {}", computed_hash);
                errors += 1;
            }

            prev_hash = Some(stored_hash.clone());
        } else {
            eprintln!("⚠️  Line {}: No record_hash (legacy record)", line_num);
            warnings += 1;
            prev_hash = None;
        }
    }

    println!();
    println!("Verification summary:");
    println!("  Total records: {}", total_records);
    println!("  Errors: {}", errors);
    println!("  Warnings: {}", warnings);
    
    if errors > 0 {
        println!();
        eprintln!("❌ Evidence log has integrity errors!");
        process::exit(1);
    } else if warnings > 0 {
        println!();
        println!("⚠️  Evidence log has warnings (likely legacy records)");
        process::exit(0);
    } else {
        println!();
        println!("✅ Evidence log integrity verified");
        process::exit(0);
    }
}

fn compute_event_hash(event: &DecisionEvent) -> Result<String, Box<dyn std::error::Error>> {
    // Create a copy without record_hash for hashing
    let mut hashable = event.clone();
    hashable.record_hash = None;

    let json = serde_json::to_string(&hashable)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}
