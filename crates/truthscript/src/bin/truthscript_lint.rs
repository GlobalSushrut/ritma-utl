// TruthScript linter CLI
// Validates TruthScript policies for syntax, semantics, and best practices

use std::env;
use std::fs;
use std::process;
use truthscript::Policy;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: truthscript_lint <policy.json>");
        eprintln!();
        eprintln!("Validates a TruthScript policy file for:");
        eprintln!("  - Syntax errors");
        eprintln!("  - Semantic issues");
        eprintln!("  - Best practice violations");
        process::exit(1);
    }

    let policy_path = &args[1];

    println!("Linting TruthScript policy: {policy_path}");
    println!();

    // Read policy file
    let content = match fs::read_to_string(policy_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Error reading file: {e}");
            process::exit(1);
        }
    };

    // Parse policy
    let policy = match Policy::from_json_str(&content) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ Syntax error: {e}");
            process::exit(1);
        }
    };

    println!("✓ Syntax valid");
    println!("  Policy: {}", policy.name);
    println!("  Version: {}", policy.version);
    println!("  Rules: {}", policy.rules.len());
    println!();

    // Run linter checks
    let mut warnings = 0;
    let mut errors = 0;

    // Check 1: Empty policy
    if policy.rules.is_empty() {
        eprintln!("⚠️  Warning: Policy has no rules");
        warnings += 1;
    }

    // Check 2: Rules with when clause but no conditions
    for (idx, rule) in policy.rules.iter().enumerate() {
        if let Some(when) = &rule.when {
            if when.conditions.is_empty() && when.event.is_none() {
                eprintln!("⚠️  Warning: Rule {idx} has 'when' clause but no conditions or event");
                warnings += 1;
            }
        }
    }

    // Check 3: Rules with no actions
    for (idx, rule) in policy.rules.iter().enumerate() {
        if rule.actions.is_empty() {
            eprintln!("⚠️  Warning: Rule {idx} has no actions");
            warnings += 1;
        }
    }

    // Check 4: Duplicate rule names
    let mut seen_names = std::collections::HashSet::new();
    for (idx, rule) in policy.rules.iter().enumerate() {
        if !seen_names.insert(&rule.name) {
            eprintln!(
                "❌ Error: Duplicate rule name '{}' at index {}",
                rule.name, idx
            );
            errors += 1;
        }
    }

    // Check 5: Conflicting actions in same rule
    for (idx, rule) in policy.rules.iter().enumerate() {
        use truthscript::Action;
        let has_deny = rule
            .actions
            .iter()
            .any(|a| matches!(a, Action::Deny { .. }));
        let has_capture_both = rule
            .actions
            .iter()
            .any(|a| matches!(a, Action::CaptureInput))
            && rule
                .actions
                .iter()
                .any(|a| matches!(a, Action::CaptureOutput));

        if has_deny && has_capture_both {
            eprintln!(
                "⚠️  Warning: Rule {idx} denies but also captures input/output (may be intentional)"
            );
            warnings += 1;
        }
    }

    // Check 7: Policy version format
    if !policy.version.contains('.') {
        eprintln!(
            "⚠️  Warning: Policy version '{}' should use semver (e.g., '1.0.0')",
            policy.version
        );
        warnings += 1;
    }

    println!();
    println!("Lint summary:");
    println!("  Errors: {errors}");
    println!("  Warnings: {warnings}");

    if errors > 0 {
        println!();
        eprintln!("❌ Policy has errors and should not be deployed");
        process::exit(1);
    } else if warnings > 0 {
        println!();
        println!("⚠️  Policy has warnings but is valid");
        process::exit(0);
    } else {
        println!();
        println!("✅ Policy is valid with no issues");
        process::exit(0);
    }
}
