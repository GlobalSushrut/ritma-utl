use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::Command;

use security_events::DecisionEvent;
#[cfg(target_os = "linux")]
use security_os::linux::CgroupV2Controller;
use security_os::{
    CgroupController, Did, DidKind, FirewallController, FlowDecision, IsolationProfile,
    IsolationScope,
};
use tracing::{info, warn};

struct LoggingFirewallController;

impl FirewallController for LoggingFirewallController {
    fn enforce_flow(&self, src: &Did, dst: &Did, decision: FlowDecision) -> Result<(), String> {
        println!(
            "[firewall] src={} dst={} decision={:?}",
            src.as_str(),
            dst.as_str(),
            decision
        );
        Ok(())
    }
}

fn derive_flow_decision(ev: &DecisionEvent) -> FlowDecision {
    // Basic mapping from policy_decision + actions to FlowDecision.
    let has_quarantine = ev.policy_actions.iter().any(|a| a == "network_quarantine");

    match ev.policy_decision.as_str() {
        "deny" => {
            if has_quarantine {
                // Network quarantine implies isolation semantics.
                FlowDecision::Isolate { ttl_secs: 300 }
            } else {
                FlowDecision::Deny
            }
        }
        "throttle" => {
            // Optional override via action like "throttle_rate_per_sec:100"; default to 100.
            let rate = ev
                .policy_actions
                .iter()
                .find_map(|a| a.strip_prefix("throttle_rate_per_sec:"))
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(100);
            FlowDecision::Throttle { rate_per_sec: rate }
        }
        "isolate" => {
            // Optional TTL override via "isolate_ttl_secs:NNN".
            let ttl = ev
                .policy_actions
                .iter()
                .find_map(|a| a.strip_prefix("isolate_ttl_secs:"))
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(300);
            FlowDecision::Isolate { ttl_secs: ttl }
        }
        _ => FlowDecision::Allow,
    }
}

fn emit_enforcement_slo(ev: &DecisionEvent, operation: &str, outcome: &str) {
    info!(
        target = "security_kit::slo",
        slo_component = "ritma_shield",
        slo_operation = operation,
        slo_outcome = outcome,
        tenant_id = ?ev.tenant_id,
        root_id = %ev.root_id,
        entity_id = %ev.entity_id,
    );
}

struct ExternalFirewallController {
    helper_path: String,
}

impl FirewallController for ExternalFirewallController {
    fn enforce_flow(&self, src: &Did, dst: &Did, decision: FlowDecision) -> Result<(), String> {
        let decision_str = match decision {
            FlowDecision::Allow => "allow",
            FlowDecision::Deny => "deny",
            FlowDecision::Throttle { .. } => "throttle",
            FlowDecision::Isolate { .. } => "isolate",
        };

        let status = Command::new(&self.helper_path)
            .arg(src.as_str())
            .arg(dst.as_str())
            .arg(decision_str)
            .status()
            .map_err(|e| format!("failed to run firewall helper {}: {}", self.helper_path, e))?;

        if !status.success() {
            return Err(format!(
                "firewall helper {} exited with {:?}",
                self.helper_path,
                status.code()
            ));
        }

        Ok(())
    }
}

fn build_firewall_controller() -> Box<dyn FirewallController> {
    if let Ok(helper) = std::env::var("SECURITY_HOST_FIREWALL_HELPER") {
        if !helper.trim().is_empty() {
            return Box::new(ExternalFirewallController {
                helper_path: helper,
            });
        }
    }
    Box::new(LoggingFirewallController)
}

trait ServiceLauncher {
    fn launch(&self, did: &Did, spec: &str) -> Result<(), String>;
    fn restart(&self, did: &Did, spec: &str) -> Result<(), String>;
    fn stop(&self, did: &Did, spec: &str) -> Result<(), String>;
}

struct SystemdServiceLauncher;

impl ServiceLauncher for SystemdServiceLauncher {
    fn launch(&self, did: &Did, spec: &str) -> Result<(), String> {
        println!("[service] launch did={} spec={}", did.as_str(), spec);
        let status = Command::new("systemctl")
            .arg("start")
            .arg(spec)
            .status()
            .map_err(|e| format!("failed to run systemctl start {spec}: {e}"))?;
        if !status.success() {
            return Err(format!(
                "systemctl start {} exited with {:?}",
                spec,
                status.code()
            ));
        }
        Ok(())
    }

    fn restart(&self, did: &Did, spec: &str) -> Result<(), String> {
        println!("[service] restart did={} spec={}", did.as_str(), spec);
        let status = Command::new("systemctl")
            .arg("restart")
            .arg(spec)
            .status()
            .map_err(|e| format!("failed to run systemctl restart {spec}: {e}"))?;
        if !status.success() {
            return Err(format!(
                "systemctl restart {} exited with {:?}",
                spec,
                status.code()
            ));
        }
        Ok(())
    }

    fn stop(&self, did: &Did, spec: &str) -> Result<(), String> {
        println!("[service] stop did={} spec={}", did.as_str(), spec);
        let status = Command::new("systemctl")
            .arg("stop")
            .arg(spec)
            .status()
            .map_err(|e| format!("failed to run systemctl stop {spec}: {e}"))?;
        if !status.success() {
            return Err(format!(
                "systemctl stop {} exited with {:?}",
                spec,
                status.code()
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn build_cgroup_controller() -> Box<dyn CgroupController> {
    if let Ok(root) = std::env::var("SECURITY_HOST_CGROUP_ROOT") {
        Box::new(CgroupV2Controller::new(root))
    } else {
        Box::new(LoggingCgroupController)
    }
}

#[cfg(not(target_os = "linux"))]
fn build_cgroup_controller() -> Box<dyn CgroupController> {
    Box::new(LoggingCgroupController)
}

struct LoggingCgroupController;

impl CgroupController for LoggingCgroupController {
    fn apply_profile(
        &self,
        scope: IsolationScope,
        did: &Did,
        profile: IsolationProfile,
    ) -> Result<(), String> {
        println!(
            "[cgroup] scope={:?} did={} profile={:?}",
            scope,
            did.as_str(),
            profile
        );
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let path = std::env::var("SECURITY_EVENTS_PATH")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());

    let stdin_flag = path == "-";
    let reader: Box<dyn BufRead> = if stdin_flag {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        let file = File::open(&path)?;
        Box::new(BufReader::new(file))
    };

    let fw = build_firewall_controller();
    let cg = build_cgroup_controller();
    let launcher = SystemdServiceLauncher;

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        let ev: DecisionEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping malformed decision event: {e}");
                continue;
            }
        };

        info!(
            target = "security_host::decision",
            ts = ev.ts,
            tenant_id = ?ev.tenant_id,
            root_id = %ev.root_id,
            entity_id = %ev.entity_id,
            kind = %ev.event_kind,
            decision = %ev.policy_decision,
            rules = ?ev.policy_rules,
            actions = ?ev.policy_actions,
        );

        if let (Some(src), Some(dst)) = (ev.src_did.as_deref(), ev.dst_did.as_deref()) {
            if let (Ok(src_did), Ok(dst_did)) = (Did::parse(src), Did::parse(dst)) {
                let flow_decision = derive_flow_decision(&ev);

                let fw_outcome =
                    if let Err(e) = fw.enforce_flow(&src_did, &dst_did, flow_decision.clone()) {
                        warn!(
                            target = "security_host::firewall",
                            src = %src_did.as_str(),
                            dst = %dst_did.as_str(),
                            error = %e,
                            "failed to enforce firewall flow",
                        );
                        "error"
                    } else {
                        "ok"
                    };
                emit_enforcement_slo(&ev, "firewall_enforce", fw_outcome);

                if !matches!(flow_decision, FlowDecision::Allow) {
                    let scope = match src_did.kind() {
                        DidKind::Tenant => IsolationScope::Tenant,
                        DidKind::Zone => IsolationScope::Zone,
                        _ => IsolationScope::Service,
                    };
                    let profile = derive_isolation_profile(&ev.policy_actions);
                    let cg_outcome = if let Err(e) = cg.apply_profile(scope, &src_did, profile) {
                        warn!(
                            target = "security_host::cgroup",
                            src = %src_did.as_str(),
                            error = %e,
                            "failed to apply cgroup profile",
                        );
                        "error"
                    } else {
                        "ok"
                    };
                    emit_enforcement_slo(&ev, "cgroup_apply", cg_outcome);
                }

                // Handle service actions based on policy_actions.
                handle_service_actions(&launcher, &src_did, &ev.policy_actions);
            }
        }
    }

    Ok(())
}

fn handle_service_actions<L: ServiceLauncher>(launcher: &L, did: &Did, actions: &[String]) {
    for act in actions {
        if let Some(spec) = act.strip_prefix("launch_service:") {
            if let Err(e) = launcher.launch(did, spec) {
                eprintln!(
                    "failed to launch service {} for did {}: {}",
                    spec,
                    did.as_str(),
                    e
                );
            }
        } else if let Some(spec) = act.strip_prefix("restart_service:") {
            if let Err(e) = launcher.restart(did, spec) {
                eprintln!(
                    "failed to restart service {} for did {}: {}",
                    spec,
                    did.as_str(),
                    e
                );
            }
        } else if let Some(spec) = act.strip_prefix("stop_service:") {
            if let Err(e) = launcher.stop(did, spec) {
                eprintln!(
                    "failed to stop service {} for did {}: {}",
                    spec,
                    did.as_str(),
                    e
                );
            }
        }
    }
}

fn derive_isolation_profile(actions: &[String]) -> IsolationProfile {
    // Default: network quarantine, no CPU/memory caps unless explicitly set.
    let mut profile = IsolationProfile {
        cpu_limit_pct: None,
        memory_limit_mb: None,
        network_egress: Some(false),
        network_ingress: Some(false),
    };

    for act in actions {
        if let Some(rest) = act.strip_prefix("limit_cpu_pct:") {
            if let Ok(v) = rest.parse::<u8>() {
                if v > 0 && v <= 100 {
                    profile.cpu_limit_pct = Some(v);
                }
            }
        } else if let Some(rest) = act.strip_prefix("limit_memory_mb:") {
            if let Ok(v) = rest.parse::<u64>() {
                if v > 0 {
                    profile.memory_limit_mb = Some(v);
                }
            }
        } else if act == "allow_egress" {
            profile.network_egress = Some(true);
        } else if act == "allow_ingress" {
            profile.network_ingress = Some(true);
        } else if act == "network_quarantine" {
            profile.network_egress = Some(false);
            profile.network_ingress = Some(false);
        }
    }

    profile
}
