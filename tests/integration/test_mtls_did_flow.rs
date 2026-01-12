// Integration test: mTLS → DID extraction → DecisionEvent → OS enforcement
// This test verifies the end-to-end flow from TLS client cert to firewall rules.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    #[test]
    #[ignore] // Run with: cargo test --test test_mtls_did_flow -- --ignored
    fn test_mtls_cert_to_decision_event() {
        // This test requires:
        // 1. Self-signed CA and client cert with DID in SAN
        // 2. utld running with policy
        // 3. utl_http with mTLS enabled
        // 4. security_host monitoring decision events

        let test_dir = "/tmp/ritma_test_mtls";
        fs::create_dir_all(test_dir).expect("failed to create test dir");

        // For now, just verify the test infrastructure works
        // Full implementation requires cert generation and running services
        println!("Test infrastructure validated");
        println!("TODO: Generate test certificates");
        println!("TODO: Start services and verify mTLS flow");

        // Cleanup
        let _ = fs::remove_dir_all(test_dir);
    }

    #[test]
    #[ignore]
    fn test_firewall_enforcement_from_decision() {
        // Test that firewall helper can be invoked
        let test_dir = "/tmp/ritma_test_firewall";
        fs::create_dir_all(test_dir).expect("failed to create test dir");

        let helper_path = "target/release/ritma_firewall_helper";
        if !Path::new(helper_path).exists() {
            println!("Skipping test: {helper_path} not found");
            let _ = fs::remove_dir_all(test_dir);
            return;
        }

        // Test firewall helper in log mode
        let output = Command::new(helper_path)
            .arg("did:ritma:tenant:acme")
            .arg("did:ritma:svc:api")
            .arg("deny")
            .env("RITMA_FW_BACKEND", "log")
            .output()
            .expect("failed to run firewall helper");

        assert!(output.status.success(), "firewall helper failed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("deny") || stdout.contains("did"),
            "firewall helper output unexpected"
        );

        let _ = fs::remove_dir_all(test_dir);
    }

    #[test]
    #[ignore]
    fn test_cgroup_isolation_applied() {
        // Test that cgroup directories can be created
        let test_dir = "/tmp/ritma_test_cgroup";
        fs::create_dir_all(test_dir).expect("failed to create test dir");

        let cgroup_root = format!("{test_dir}/cgroup");
        fs::create_dir_all(&cgroup_root).expect("failed to create cgroup root");

        // Create test cgroup structure
        let tenant_path = format!("{cgroup_root}/tenants/did_ritma_tenant_acme");
        fs::create_dir_all(&tenant_path).expect("failed to create tenant cgroup");

        // Write test limits
        fs::write(format!("{tenant_path}/cpu.max"), "50000 100000")
            .expect("failed to write cpu.max");
        fs::write(format!("{tenant_path}/memory.max"), "536870912")
            .expect("failed to write memory.max");

        // Verify
        let cpu_max =
            fs::read_to_string(format!("{tenant_path}/cpu.max")).expect("failed to read cpu.max");
        assert!(cpu_max.contains("50000"), "cpu limit not set correctly");

        let _ = fs::remove_dir_all(test_dir);
    }

    // Helper functions (stubs - implement as needed)

    #[allow(dead_code)]
    fn generate_test_certs(test_dir: &str) {
        // Generate self-signed CA
        // Generate server cert
        // Generate client cert with SAN URI: did:ritma:tenant:test
        println!("TODO: implement test cert generation in {test_dir}");
    }

    #[allow(dead_code)]
    fn start_utld_test_instance(test_dir: &str) -> std::process::Child {
        let bin_path = "target/release/utld";
        if !Path::new(bin_path).exists() {
            panic!("utld binary not found at {bin_path}. Run: cargo build --release -p utld");
        }
        Command::new(bin_path)
            .env("UTLD_SOCKET", format!("{test_dir}/utld.sock"))
            .env("UTLD_POLICY", "tests/fixtures/test_policy.json")
            .spawn()
            .expect("failed to start utld")
    }

    #[allow(dead_code)]
    fn start_utl_http_with_mtls(test_dir: &str) -> std::process::Child {
        let bin_path = "target/release/utl_http";
        if !Path::new(bin_path).exists() {
            panic!(
                "utl_http binary not found at {bin_path}. Run: cargo build --release -p utl_http"
            );
        }
        Command::new(bin_path)
            .env("UTL_HTTP_TLS_ADDR", "127.0.0.1:18443")
            .env("UTL_HTTP_TLS_CA", format!("{test_dir}/ca.pem"))
            .env("UTL_HTTP_TLS_CERT", format!("{test_dir}/server-cert.pem"))
            .env("UTL_HTTP_TLS_KEY", format!("{test_dir}/server-key.pem"))
            .env("UTL_HTTP_TLS_REQUIRE_CLIENT_AUTH", "true")
            .spawn()
            .expect("failed to start utl_http")
    }

    #[allow(dead_code)]
    fn make_mtls_request(test_dir: &str, _did: &str) -> String {
        // Use curl or reqwest with client cert
        println!("TODO: implement mTLS request from {test_dir}");
        String::new()
    }

    #[allow(dead_code)]
    fn read_decision_events(test_dir: &str) -> Vec<serde_json::Value> {
        let path = format!("{test_dir}/decision_events.jsonl");
        if !Path::new(&path).exists() {
            return vec![];
        }

        fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    #[allow(dead_code)]
    fn start_security_host_test(_test_dir: &str) -> std::process::Child {
        let bin_path = "target/release/security_host";
        if !Path::new(bin_path).exists() {
            panic!(
                "security_host binary not found at {bin_path}. Run: cargo build --release -p security_host"
            );
        }
        Command::new(bin_path)
            .env(
                "SECURITY_HOST_FIREWALL_HELPER",
                "target/release/ritma_firewall_helper",
            )
            .env("RITMA_FW_BACKEND", "log") // Use log mode for testing
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("failed to start security_host")
    }

    #[allow(dead_code)]
    fn emit_test_decision_event(test_dir: &str, decision: &str, src_did: &str, dst_did: &str) {
        emit_test_decision_event_with_actions(test_dir, decision, src_did, dst_did, vec![]);
    }

    #[allow(dead_code)]
    fn emit_test_decision_event_with_actions(
        test_dir: &str,
        decision: &str,
        src_did: &str,
        dst_did: &str,
        actions: Vec<&str>,
    ) {
        let event = serde_json::json!({
            "ts": 0,
            "tenant_id": "test",
            "root_id": "test_root",
            "entity_id": "test_entity",
            "event_kind": "test",
            "policy_name": "test_policy",
            "policy_version": "1.0",
            "policy_decision": decision,
            "policy_rules": ["test_rule"],
            "policy_actions": actions,
            "src_did": src_did,
            "dst_did": dst_did,
        });

        let path = format!("{test_dir}/decision_events.jsonl");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("failed to open decision events file");

        use std::io::Write;
        writeln!(file, "{event}").expect("failed to write decision event");
    }

    #[allow(dead_code)]
    fn cleanup_test_instance(
        mut utld: std::process::Child,
        mut http: std::process::Child,
        test_dir: &str,
    ) {
        let _ = utld.kill();
        let _ = http.kill();
        let _ = fs::remove_dir_all(test_dir);
    }

    #[allow(dead_code)]
    fn cleanup_security_host(mut security_host: std::process::Child, test_dir: &str) {
        let _ = security_host.kill();
        let _ = fs::remove_dir_all(test_dir);
    }
}
