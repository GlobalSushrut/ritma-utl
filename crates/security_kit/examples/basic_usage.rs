/// Basic SecurityKit usage example showing the developer-facing API.
///
/// Run with: cargo run --example basic_usage
use security_kit::{
    connectors::ConnectorKind,
    containers::{GeneralParams, ParamBundle, SecretParams, SnapshotParams},
    env::EnvManager,
    rbac::{Permission, RbacManager, Role, RoleId, User, UserId},
    reporting::SecurityReport,
    SecurityKit,
};
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SecurityKit Basic Usage Example ===\n");

    // 1. Build environment manager
    let mut env = EnvManager::new().with_tenant("acme_corp");

    env.set_general("APP_ENV", "production");
    env.set_general("LOG_LEVEL", "info");
    env.set_secret("DATABASE_URL", "postgres://...");
    env.set_secret("API_KEY", "sk_live_...");

    println!("Environment configured:");
    for line in env.to_env_lines() {
        println!("  {line}");
    }
    println!();

    // 2. Build RBAC manager
    let mut rbac = RbacManager::new();

    // Define roles
    let admin_role = Role {
        id: RoleId("admin".to_string()),
        permissions: vec![
            Permission("read".to_string()),
            Permission("write".to_string()),
            Permission("deploy".to_string()),
        ]
        .into_iter()
        .collect(),
    };

    let viewer_role = Role {
        id: RoleId("viewer".to_string()),
        permissions: vec![Permission("read".to_string())].into_iter().collect(),
    };

    rbac.upsert_role(admin_role);
    rbac.upsert_role(viewer_role);

    // Define users
    let alice = User {
        id: UserId("alice".to_string()),
        roles: vec![RoleId("admin".to_string())].into_iter().collect(),
    };

    let bob = User {
        id: UserId("bob".to_string()),
        roles: vec![RoleId("viewer".to_string())].into_iter().collect(),
    };

    rbac.upsert_user(alice);
    rbac.upsert_user(bob);

    println!("RBAC configured:");
    println!(
        "  alice can deploy: {}",
        rbac.check(
            &UserId("alice".to_string()),
            &Permission("deploy".to_string())
        )?
    );
    println!(
        "  bob can deploy: {}",
        rbac.check(
            &UserId("bob".to_string()),
            &Permission("deploy".to_string())
        )?
    );
    println!(
        "  bob can read: {}",
        rbac.check(&UserId("bob".to_string()), &Permission("read".to_string()))?
    );
    println!();

    // 3. Build SecurityKit with connectors
    let _kit = SecurityKit::builder()
        .with_env(env)
        .with_rbac(rbac)
        .add_noop_connector("aws-prod", ConnectorKind::Aws)
        .add_kubernetes_connector("k8s-cluster")
        .add_noop_connector("gcs-storage", ConnectorKind::Storage)
        .build()?;

    println!("SecurityKit built with 3 connectors");
    println!();

    // 4. Create a param bundle for pipeline dry-run
    let mut general = BTreeMap::new();
    general.insert("region".to_string(), "us-east-1".to_string());
    general.insert("cluster".to_string(), "prod-cluster".to_string());

    let mut secrets = BTreeMap::new();
    secrets.insert("kube_token".to_string(), "eyJ...".to_string());

    let snapshot = SnapshotParams {
        label: "deployment-v1.2.3".to_string(),
        ts: 1702400000,
        fields: vec![
            ("git_sha".to_string(), "abc123".to_string()),
            ("deployer".to_string(), "alice".to_string()),
        ]
        .into_iter()
        .collect(),
    };

    let bundle = ParamBundle {
        general: GeneralParams(general),
        secrets: SecretParams(secrets),
        snapshot: Some(snapshot),
    };

    println!("Param bundle created:");
    println!("  general keys: {}", bundle.general.0.len());
    println!("  secret keys: {}", bundle.secrets.0.len());
    println!(
        "  snapshot: {:?}",
        bundle.snapshot.as_ref().map(|s| &s.label)
    );
    println!();

    // 5. Dry-run connectors (safe validation)
    let builder = SecurityKit::builder()
        .add_noop_connector("aws-prod", ConnectorKind::Aws)
        .add_kubernetes_connector("k8s-cluster");

    builder.dry_run_connectors(&bundle)?;
    println!("✓ Connector dry-run passed");
    println!();

    // 6. Generate a security report from params
    let report = SecurityReport::from_params("Deployment Security Report", &bundle);
    let report_json = serde_json::to_string_pretty(&report)?;

    println!("Security Report (from params):");
    println!("{report_json}");
    println!();

    // 7. Try to generate full infra report (will be empty if no logs exist)
    match SecurityReport::generate_for_tenant(Some("acme_corp")) {
        Ok(infra_report) => {
            println!("Infra Report (from logs):");
            println!("  Controls: {}", infra_report.control_posture.len());
            println!("  Incidents: {}", infra_report.incidents.len());
            println!("  Dig Coverage: {}", infra_report.dig_coverage.len());
        }
        Err(e) => {
            println!("Infra report not available (logs not present): {e}");
        }
    }

    println!("\n=== Example Complete ===");
    Ok(())
}
