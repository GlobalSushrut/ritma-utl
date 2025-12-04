use std::fs::File;
use std::io::{BufRead, BufReader};

use security_events::DecisionEvent;
use security_os::{CgroupController, Did, FlowDecision, FirewallController, IsolationProfile, IsolationScope};

struct LoggingFirewallController;

impl FirewallController for LoggingFirewallController {
    fn enforce_flow(&self, src: &Did, dst: &Did, decision: FlowDecision) -> Result<(), String> {
        println!("[firewall] src={} dst={} decision={:?}", src.as_str(), dst.as_str(), decision);
        Ok(())
    }
}

struct LoggingCgroupController;

impl CgroupController for LoggingCgroupController {
    fn apply_profile(&self, scope: IsolationScope, did: &Did, profile: IsolationProfile) -> Result<(), String> {
        println!("[cgroup] scope={:?} did={} profile={:?}", scope, did.as_str(), profile);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var("SECURITY_EVENTS_PATH").unwrap_or_else(|_| "./decision_events.jsonl".to_string());
    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    let fw = LoggingFirewallController;
    let cg = LoggingCgroupController;

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        let ev: DecisionEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping malformed decision event: {}", e);
                continue;
            }
        };

        println!(
            "[decision] ts={} tenant={:?} root_id={} entity_id={} kind={} decision={} rules={:?} actions={:?}",
            ev.ts, ev.tenant_id, ev.root_id, ev.entity_id, ev.event_kind, ev.policy_decision, ev.policy_rules, ev.policy_actions
        );

        // If we have DIDs, demonstrate how a host agent would call controllers.
        if let (Some(src), Some(dst)) = (ev.src_did.as_deref(), ev.dst_did.as_deref()) {
            if let (Ok(src_did), Ok(dst_did)) = (Did::parse(src), Did::parse(dst)) {
                let flow_decision = match ev.policy_decision.as_str() {
                    "deny" => FlowDecision::Deny,
                    _ => FlowDecision::Allow,
                };
                let _ = fw.enforce_flow(&src_did, &dst_did, flow_decision);
            }
        }

        // If we had isolation profiles encoded in the event, we could also call cg.apply_profile here.
        let _ = &cg; // suppress unused warning for now.
    }

    Ok(())
}
