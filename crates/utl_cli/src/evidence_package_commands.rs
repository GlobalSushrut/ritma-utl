
 use evidence_package::{
     EvidencePackageManifest, PackageBuilder, PackageScope, PackageSigner, PackageVerifier, SigningKey,
 };
 use node_keystore::NodeKeystore;
 
 fn parse_scope(scope_type: &str, scope_id: &str, framework: Option<&str>) -> Result<PackageScope, String> {
     match scope_type {
         "policy_commit" | "commit" => Ok(PackageScope::PolicyCommit {
             commit_id: scope_id.to_string(),
             framework: framework.map(|s| s.to_string()),
         }),
         "burn" | "compliance_burn" => {
             let fw = framework.ok_or_else(|| "framework is required for burn scope".to_string())?;
             Ok(PackageScope::ComplianceBurn {
                 burn_id: scope_id.to_string(),
                 framework: fw.to_string(),
             })
         }
         "incident" => {
             // scope_id format: incident_id:start:end
             let parts: Vec<&str> = scope_id.split(':').collect();
             if parts.len() != 3 {
                 return Err("incident scope_id must be incident_id:start:end".to_string());
             }
             let incident_id = parts[0].to_string();
             let start = parts[1]
                 .parse::<u64>()
                 .map_err(|e| format!("invalid incident start time: {}", e))?;
             let end = parts[2]
                 .parse::<u64>()
                 .map_err(|e| format!("invalid incident end time: {}", e))?;
             Ok(PackageScope::Incident {
                 incident_id,
                 time_start: start,
                 time_end: end,
             })
         }
         "time_range" | "time" => {
             let parts: Vec<&str> = scope_id.split(':').collect();
             if parts.len() != 2 {
                 return Err("time_range scope_id must be start:end".to_string());
             }
             let start = parts[0]
                 .parse::<u64>()
                 .map_err(|e| format!("invalid start time: {}", e))?;
             let end = parts[1]
                 .parse::<u64>()
                 .map_err(|e| format!("invalid end time: {}", e))?;
             Ok(PackageScope::TimeRange {
                 time_start: start,
                 time_end: end,
                 framework: framework.map(|s| s.to_string()),
             })
         }
         _ => Err(format!("unsupported scope_type: {}", scope_type)),
     }
 }

 pub fn cmd_evidence_package_export(
     tenant: &str,
     scope_type: &str,
     scope_id: &str,
     framework: Option<&str>,
     out: Option<&str>,
     requester_did: Option<&str>,
 ) -> Result<(), String> {
     let scope = parse_scope(scope_type, scope_id, framework)?;

     let dig_index_db = std::env::var("UTLD_DIG_INDEX_DB").unwrap_or_else(|_| "./dig_index.sqlite".to_string());
     let dig_storage = std::env::var("UTLD_DIG_STORAGE").unwrap_or_else(|_| "./digs".to_string());
     let burn_storage = std::env::var("UTLD_BURN_STORAGE").unwrap_or_else(|_| "./burns".to_string());

     let mut builder = PackageBuilder::new(tenant.to_string(), scope)
         .dig_index_db(dig_index_db)
         .dig_storage_root(dig_storage)
         .burn_storage_root(burn_storage);

     if let Some(did) = requester_did {
         builder = builder.created_by(did.to_string());
     }

     let mut manifest = builder
         .build()
         .map_err(|e| format!("failed to build package: {}", e))?;

     // Prefer node keystore for signing if configured.
     let mut signed = false;
     if let Ok(key_id) = std::env::var("RITMA_KEY_ID") {
         match NodeKeystore::from_env().and_then(|ks| ks.key_for_signing(&key_id)) {
             Ok(keystore_key) => {
                 let signing_key = SigningKey::from_hex(&keystore_key.key_type, &keystore_key.key_material)
                     .map_err(|e| format!("invalid keystore key (key_id={}): {}", key_id, e))?;
                 let signer = PackageSigner::new(signing_key, "utl_cli".to_string());
                 signer
                     .sign(&mut manifest)
                     .map_err(|e| format!("failed to sign package with keystore key {}: {}", key_id, e))?;
                 eprintln!(
                     "Package signed with keystore key_id={} signer_id={}",
                     key_id,
                     manifest
                         .security
                         .signature
                         .as_ref()
                         .map(|s| s.signer_id.as_str())
                         .unwrap_or("<unknown>"),
                 );
                 signed = true;
             }
             Err(e) => {
                 eprintln!(
                     "Warning: failed to load signing key from node keystore (key_id={}): {}",
                     key_id, e
                 );
             }
         }
     }

     // Fallback to legacy env-based signing if keystore signing was not used.
     if !signed {
         if let Ok(signer) = PackageSigner::from_env("UTLD_PACKAGE_SIG_KEY", "utl_cli".to_string()) {
             signer
                 .sign(&mut manifest)
                 .map_err(|e| format!("failed to sign package: {}", e))?;
             eprintln!(
                 "Package signed with {}",
                 manifest
                     .security
                     .signature
                     .as_ref()
                     .map(|s| s.signer_id.as_str())
                     .unwrap_or("<unknown>"),
             );
         } else {
             // No signing key configured - compute hash anyway for unsigned packages.
             let package_hash = manifest
                 .compute_hash()
                 .map_err(|e| format!("failed to compute package hash: {}", e))?;
             manifest.security.package_hash = package_hash;
             eprintln!(
                 "Warning: neither node keystore (RITMA_KEY_ID/RITMA_KEYSTORE_PATH) nor UTLD_PACKAGE_SIG_KEY are configured; package will be unsigned",
             );
         }
     }

     let json = serde_json::to_string_pretty(&manifest)
         .map_err(|e| format!("failed to serialize manifest: {}", e))?;
     if let Some(path) = out {
         std::fs::write(path, json).map_err(|e| format!("failed to write {}: {}", path, e))?;
         eprintln!("Evidence package written to: {}", path);
     } else {
         println!("{}", json);
     }

     eprintln!("Package ID: {}", manifest.package_id);
     eprintln!("Artifacts: {}", manifest.artifacts.len());
     eprintln!("Package hash: {}", manifest.security.package_hash);

     Ok(())
 }

 pub fn cmd_evidence_package_verify(manifest_path: &str, skip_artifacts: bool) -> Result<(), String> {
     let content = std::fs::read_to_string(manifest_path)
         .map_err(|e| format!("failed to read manifest {}: {}", manifest_path, e))?;
     let manifest: EvidencePackageManifest =
         serde_json::from_str(&content).map_err(|e| format!("failed to parse manifest: {}", e))?;

     let mut verifier = PackageVerifier::new();
     if skip_artifacts {
         verifier = verifier.skip_artifacts();
     }

     let result = verifier.verify(&manifest);

     println!("Package ID: {}", result.package_id);
     println!("Hash valid: {}", result.hash_valid);
     println!("Signature valid: {}", result.signature_valid);
     println!("Artifacts verified: {}", result.artifacts_verified);
     println!("Artifacts failed: {}", result.artifacts_failed);

     if !result.errors.is_empty() {
         println!("\nErrors:");
         for err in &result.errors {
             println!("  - {}", err);
         }
     }

     let demo_allow_unsigned = std::env::var("RITMA_DEMO_ALLOW_UNSIGNED")
         .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
         .unwrap_or(false);

     if result.is_valid() {
         println!("\n    Package verification PASSED");
         Ok(())
     } else if demo_allow_unsigned && result.hash_valid && !result.signature_valid && result.artifacts_failed == 0 {
         println!("\n[demo-note] Package verification is in DEMO MODE (RITMA_DEMO_ALLOW_UNSIGNED=1).");
         println!("[demo-note] Hash is cryptographically valid, but no signing key is configured.");
         println!("[demo-note] For this demo, unsigned but hash-valid packages are treated as SUCCESS.");
         println!("[demo-note] In pilot/production, configure a signing key to require valid signatures.");
         println!("\n    Package verification PASSED (demo mode: unsigned, hash-valid)");
         Ok(())
     } else {
         println!("\n    Package verification FAILED");
         Err("verification failed".to_string())
     }
 }
