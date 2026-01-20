//! SLSA Provenance and SBOM (Software Bill of Materials)
//!
//! Capability #6: Build→Deploy→Run linkage with:
//! - SLSA provenance attestations
//! - SBOM generation and verification
//! - Build reproducibility tracking
//! - Deployment chain records

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// SLSA Provenance (Supply-chain Levels for Software Artifacts)
// ============================================================================

/// SLSA Build Level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlsaLevel {
    /// No guarantees
    Level0,
    /// Documentation of build process
    Level1,
    /// Hosted build platform, signed provenance
    Level2,
    /// Hardened builds, non-falsifiable provenance
    Level3,
    /// Two-party review, hermetic builds
    Level4,
}

impl SlsaLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Level0 => "slsa-0",
            Self::Level1 => "slsa-1",
            Self::Level2 => "slsa-2",
            Self::Level3 => "slsa-3",
            Self::Level4 => "slsa-4",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "slsa-0" | "0" => Some(Self::Level0),
            "slsa-1" | "1" => Some(Self::Level1),
            "slsa-2" | "2" => Some(Self::Level2),
            "slsa-3" | "3" => Some(Self::Level3),
            "slsa-4" | "4" => Some(Self::Level4),
            _ => None,
        }
    }
}

/// SLSA Provenance Predicate (v1.0 format)
#[derive(Debug, Clone)]
pub struct SlsaProvenance {
    /// Build definition
    pub build_definition: BuildDefinition,
    /// Run details
    pub run_details: RunDetails,
}

#[derive(Debug, Clone)]
pub struct BuildDefinition {
    /// Build type URI
    pub build_type: String,
    /// External parameters
    pub external_parameters: BTreeMap<String, String>,
    /// Internal parameters
    pub internal_parameters: BTreeMap<String, String>,
    /// Resolved dependencies
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

#[derive(Debug, Clone)]
pub struct RunDetails {
    /// Builder info
    pub builder: BuilderInfo,
    /// Build metadata
    pub metadata: BuildMetadata,
    /// Byproducts
    pub byproducts: Vec<ResourceDescriptor>,
}

#[derive(Debug, Clone)]
pub struct BuilderInfo {
    /// Builder ID (URI)
    pub id: String,
    /// Builder version
    pub version: Option<String>,
    /// Builder dependencies
    pub builder_dependencies: Vec<ResourceDescriptor>,
}

#[derive(Debug, Clone)]
pub struct BuildMetadata {
    /// Invocation ID
    pub invocation_id: String,
    /// Started at (RFC3339)
    pub started_on: String,
    /// Finished at (RFC3339)
    pub finished_on: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResourceDescriptor {
    /// URI of the resource
    pub uri: String,
    /// Digest (algorithm -> hex value)
    pub digest: BTreeMap<String, String>,
    /// Name
    pub name: Option<String>,
    /// Download location
    pub download_location: Option<String>,
    /// Media type
    pub media_type: Option<String>,
    /// Content (for inline resources)
    pub content: Option<Vec<u8>>,
    /// Annotations
    pub annotations: BTreeMap<String, String>,
}

impl ResourceDescriptor {
    pub fn new(uri: &str) -> Self {
        Self {
            uri: uri.to_string(),
            digest: BTreeMap::new(),
            name: None,
            download_location: None,
            media_type: None,
            content: None,
            annotations: BTreeMap::new(),
        }
    }

    pub fn with_sha256(mut self, hash: &[u8; 32]) -> Self {
        self.digest.insert("sha256".to_string(), hex::encode(hash));
        self
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }
}

impl SlsaProvenance {
    /// Create a new provenance record
    pub fn new(build_type: &str, builder_id: &str) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let invocation_id = {
            let mut h = Sha256::new();
            h.update(b"slsa-invocation@0.1");
            h.update(builder_id.as_bytes());
            h.update(now.as_bytes());
            format!("inv-{}", hex::encode(&h.finalize()[..16]))
        };

        Self {
            build_definition: BuildDefinition {
                build_type: build_type.to_string(),
                external_parameters: BTreeMap::new(),
                internal_parameters: BTreeMap::new(),
                resolved_dependencies: Vec::new(),
            },
            run_details: RunDetails {
                builder: BuilderInfo {
                    id: builder_id.to_string(),
                    version: None,
                    builder_dependencies: Vec::new(),
                },
                metadata: BuildMetadata {
                    invocation_id,
                    started_on: now,
                    finished_on: None,
                },
                byproducts: Vec::new(),
            },
        }
    }

    /// Add a resolved dependency
    pub fn add_dependency(&mut self, dep: ResourceDescriptor) {
        self.build_definition.resolved_dependencies.push(dep);
    }

    /// Add a byproduct
    pub fn add_byproduct(&mut self, byproduct: ResourceDescriptor) {
        self.run_details.byproducts.push(byproduct);
    }

    /// Mark build as finished
    pub fn finish(&mut self) {
        self.run_details.metadata.finished_on = Some(chrono::Utc::now().to_rfc3339());
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let deps: Vec<_> = self
            .build_definition
            .resolved_dependencies
            .iter()
            .map(|d| (&d.uri, &d.digest, &d.name))
            .collect();
        let byproducts: Vec<_> = self
            .run_details
            .byproducts
            .iter()
            .map(|b| (&b.uri, &b.digest, &b.name))
            .collect();

        let tuple = (
            "slsa-provenance@1.0",
            &self.build_definition.build_type,
            &self.build_definition.external_parameters,
            deps,
            &self.run_details.builder.id,
            &self.run_details.builder.version,
            &self.run_details.metadata.invocation_id,
            &self.run_details.metadata.started_on,
            &self.run_details.metadata.finished_on,
            byproducts,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }

    /// Compute provenance digest
    pub fn digest(&self) -> [u8; 32] {
        let cbor = self.to_cbor();
        let mut h = Sha256::new();
        h.update(&cbor);
        h.finalize().into()
    }
}

// ============================================================================
// SBOM (Software Bill of Materials)
// ============================================================================

/// SBOM format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    /// CycloneDX
    CycloneDx,
    /// SPDX
    Spdx,
    /// Custom Ritma format
    Ritma,
}

/// SBOM Component
#[derive(Debug, Clone)]
pub struct SbomComponent {
    /// Component type
    pub component_type: ComponentType,
    /// Name
    pub name: String,
    /// Version
    pub version: String,
    /// Package URL (purl)
    pub purl: Option<String>,
    /// Licenses
    pub licenses: Vec<String>,
    /// Hashes
    pub hashes: BTreeMap<String, String>,
    /// Dependencies (component names)
    pub dependencies: Vec<String>,
    /// Properties
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentType {
    Application,
    Library,
    Framework,
    Container,
    OperatingSystem,
    Device,
    File,
    Data,
}

impl ComponentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Library => "library",
            Self::Framework => "framework",
            Self::Container => "container",
            Self::OperatingSystem => "operating-system",
            Self::Device => "device",
            Self::File => "file",
            Self::Data => "data",
        }
    }
}

impl SbomComponent {
    pub fn new(component_type: ComponentType, name: &str, version: &str) -> Self {
        Self {
            component_type,
            name: name.to_string(),
            version: version.to_string(),
            purl: None,
            licenses: Vec::new(),
            hashes: BTreeMap::new(),
            dependencies: Vec::new(),
            properties: BTreeMap::new(),
        }
    }

    pub fn with_purl(mut self, purl: &str) -> Self {
        self.purl = Some(purl.to_string());
        self
    }

    pub fn with_sha256(mut self, hash: &[u8; 32]) -> Self {
        self.hashes.insert("SHA-256".to_string(), hex::encode(hash));
        self
    }

    pub fn add_license(mut self, license: &str) -> Self {
        self.licenses.push(license.to_string());
        self
    }
}

/// Software Bill of Materials
#[derive(Debug, Clone)]
pub struct Sbom {
    /// SBOM format
    pub format: SbomFormat,
    /// Serial number / ID
    pub serial_number: String,
    /// Version
    pub version: u32,
    /// Timestamp
    pub timestamp: String,
    /// Tool that generated the SBOM
    pub tool: String,
    /// Components
    pub components: Vec<SbomComponent>,
    /// Metadata
    pub metadata: BTreeMap<String, String>,
}

impl Sbom {
    pub fn new(format: SbomFormat, tool: &str) -> Self {
        let now = chrono::Utc::now();
        let serial = {
            let mut h = Sha256::new();
            h.update(b"sbom-serial@0.1");
            h.update(now.to_rfc3339().as_bytes());
            format!("urn:uuid:{}", hex::encode(&h.finalize()[..16]))
        };

        Self {
            format,
            serial_number: serial,
            version: 1,
            timestamp: now.to_rfc3339(),
            tool: tool.to_string(),
            components: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn add_component(&mut self, component: SbomComponent) {
        self.components.push(component);
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let components: Vec<_> = self
            .components
            .iter()
            .map(|c| {
                (
                    c.component_type.as_str(),
                    &c.name,
                    &c.version,
                    &c.purl,
                    &c.licenses,
                    &c.hashes,
                    &c.dependencies,
                )
            })
            .collect();

        let tuple = (
            "ritma-sbom@1.0",
            match self.format {
                SbomFormat::CycloneDx => "cyclonedx",
                SbomFormat::Spdx => "spdx",
                SbomFormat::Ritma => "ritma",
            },
            &self.serial_number,
            self.version,
            &self.timestamp,
            &self.tool,
            components,
            &self.metadata,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }

    /// Compute SBOM digest
    pub fn digest(&self) -> [u8; 32] {
        let cbor = self.to_cbor();
        let mut h = Sha256::new();
        h.update(&cbor);
        h.finalize().into()
    }
}

// ============================================================================
// Build→Deploy→Run Linkage
// ============================================================================

/// Deployment record linking build to runtime
#[derive(Debug, Clone)]
pub struct DeploymentRecord {
    /// Deployment ID
    pub deployment_id: String,
    /// Build provenance digest
    pub provenance_digest: [u8; 32],
    /// SBOM digest
    pub sbom_digest: [u8; 32],
    /// Target environment
    pub environment: String,
    /// Deployment timestamp
    pub deployed_at: String,
    /// Deployer identity
    pub deployer: String,
    /// Runtime configuration hash
    pub config_hash: [u8; 32],
    /// Signature
    pub signature: Option<String>,
}

impl DeploymentRecord {
    pub fn new(
        provenance_digest: [u8; 32],
        sbom_digest: [u8; 32],
        environment: &str,
        deployer: &str,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let deployment_id = {
            let mut h = Sha256::new();
            h.update(b"deployment@0.1");
            h.update(&provenance_digest);
            h.update(&sbom_digest);
            h.update(now.as_bytes());
            format!("deploy-{}", hex::encode(&h.finalize()[..16]))
        };

        Self {
            deployment_id,
            provenance_digest,
            sbom_digest,
            environment: environment.to_string(),
            deployed_at: now,
            deployer: deployer.to_string(),
            config_hash: [0u8; 32],
            signature: None,
        }
    }

    pub fn with_config_hash(mut self, hash: [u8; 32]) -> Self {
        self.config_hash = hash;
        self
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-deployment@0.1",
            &self.deployment_id,
            hex::encode(self.provenance_digest),
            hex::encode(self.sbom_digest),
            &self.environment,
            &self.deployed_at,
            &self.deployer,
            hex::encode(self.config_hash),
            &self.signature,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

/// Runtime attestation linking deployment to running instance
#[derive(Debug, Clone)]
pub struct RuntimeAttestation {
    /// Attestation ID
    pub attestation_id: String,
    /// Deployment ID
    pub deployment_id: String,
    /// Node ID
    pub node_id: String,
    /// Process ID
    pub pid: u32,
    /// Started at
    pub started_at: String,
    /// Binary hash (at runtime)
    pub binary_hash: [u8; 32],
    /// Memory layout hash
    pub memory_hash: Option<[u8; 32]>,
    /// Environment variables hash
    pub env_hash: [u8; 32],
}

impl RuntimeAttestation {
    pub fn new(deployment_id: &str, node_id: &str, pid: u32, binary_hash: [u8; 32]) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let attestation_id = {
            let mut h = Sha256::new();
            h.update(b"runtime-attestation@0.1");
            h.update(deployment_id.as_bytes());
            h.update(node_id.as_bytes());
            h.update(&pid.to_le_bytes());
            h.update(now.as_bytes());
            format!("attest-{}", hex::encode(&h.finalize()[..16]))
        };

        Self {
            attestation_id,
            deployment_id: deployment_id.to_string(),
            node_id: node_id.to_string(),
            pid,
            started_at: now,
            binary_hash,
            memory_hash: None,
            env_hash: [0u8; 32],
        }
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-runtime-attest@0.1",
            &self.attestation_id,
            &self.deployment_id,
            &self.node_id,
            self.pid,
            &self.started_at,
            hex::encode(self.binary_hash),
            self.memory_hash.map(hex::encode),
            hex::encode(self.env_hash),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

// ============================================================================
// Provenance Chain
// ============================================================================

/// Complete provenance chain from build to runtime
#[derive(Debug, Clone)]
pub struct ProvenanceChain {
    /// SLSA provenance
    pub provenance: SlsaProvenance,
    /// SBOM
    pub sbom: Sbom,
    /// Deployment record
    pub deployment: Option<DeploymentRecord>,
    /// Runtime attestation
    pub runtime: Option<RuntimeAttestation>,
}

impl ProvenanceChain {
    pub fn new(provenance: SlsaProvenance, sbom: Sbom) -> Self {
        Self {
            provenance,
            sbom,
            deployment: None,
            runtime: None,
        }
    }

    pub fn with_deployment(mut self, deployment: DeploymentRecord) -> Self {
        self.deployment = Some(deployment);
        self
    }

    pub fn with_runtime(mut self, runtime: RuntimeAttestation) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Verify chain integrity
    pub fn verify(&self) -> ProvenanceVerification {
        let mut issues = Vec::new();

        // Check provenance has dependencies
        if self
            .provenance
            .build_definition
            .resolved_dependencies
            .is_empty()
        {
            issues.push("No resolved dependencies in provenance".to_string());
        }

        // Check SBOM has components
        if self.sbom.components.is_empty() {
            issues.push("No components in SBOM".to_string());
        }

        // Check deployment links to provenance
        if let Some(ref deploy) = self.deployment {
            let prov_digest = self.provenance.digest();
            if deploy.provenance_digest != prov_digest {
                issues.push("Deployment provenance digest mismatch".to_string());
            }
            let sbom_digest = self.sbom.digest();
            if deploy.sbom_digest != sbom_digest {
                issues.push("Deployment SBOM digest mismatch".to_string());
            }
        }

        // Check runtime links to deployment
        if let (Some(ref runtime), Some(ref deploy)) = (&self.runtime, &self.deployment) {
            if runtime.deployment_id != deploy.deployment_id {
                issues.push("Runtime deployment ID mismatch".to_string());
            }
        }

        ProvenanceVerification {
            valid: issues.is_empty(),
            issues,
            provenance_digest: self.provenance.digest(),
            sbom_digest: self.sbom.digest(),
        }
    }

    /// Serialize entire chain to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-provenance-chain@0.1",
            self.provenance.to_cbor(),
            self.sbom.to_cbor(),
            self.deployment.as_ref().map(|d| d.to_cbor()),
            self.runtime.as_ref().map(|r| r.to_cbor()),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

#[derive(Debug, Clone)]
pub struct ProvenanceVerification {
    pub valid: bool,
    pub issues: Vec<String>,
    pub provenance_digest: [u8; 32],
    pub sbom_digest: [u8; 32],
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slsa_level() {
        assert_eq!(SlsaLevel::Level3.as_str(), "slsa-3");
        assert_eq!(SlsaLevel::from_str("slsa-2"), Some(SlsaLevel::Level2));
        assert!(SlsaLevel::Level4 > SlsaLevel::Level1);
    }

    #[test]
    fn test_slsa_provenance() {
        let mut prov = SlsaProvenance::new(
            "https://ritma.dev/build/v1",
            "https://github.com/actions/runner",
        );

        prov.add_dependency(
            ResourceDescriptor::new("pkg:cargo/ritma@0.1.0")
                .with_sha256(&[0xaa; 32])
                .with_name("ritma"),
        );

        prov.finish();

        let cbor = prov.to_cbor();
        assert!(!cbor.is_empty());

        let digest = prov.digest();
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn test_sbom() {
        let mut sbom = Sbom::new(SbomFormat::Ritma, "ritma-cli");

        sbom.add_component(
            SbomComponent::new(ComponentType::Library, "sha2", "0.10.0")
                .with_purl("pkg:cargo/sha2@0.10.0")
                .add_license("MIT"),
        );

        sbom.add_component(
            SbomComponent::new(ComponentType::Library, "ciborium", "0.2.0")
                .with_purl("pkg:cargo/ciborium@0.2.0")
                .add_license("Apache-2.0"),
        );

        let cbor = sbom.to_cbor();
        assert!(!cbor.is_empty());

        let digest = sbom.digest();
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn test_deployment_record() {
        let prov_digest = [0xaa; 32];
        let sbom_digest = [0xbb; 32];

        let deploy = DeploymentRecord::new(prov_digest, sbom_digest, "production", "deploy-bot")
            .with_config_hash([0xcc; 32]);

        assert!(!deploy.deployment_id.is_empty());

        let cbor = deploy.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_runtime_attestation() {
        let attest = RuntimeAttestation::new("deploy-abc123", "node1", 12345, [0xdd; 32]);

        assert!(!attest.attestation_id.is_empty());

        let cbor = attest.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_provenance_chain() {
        let mut prov = SlsaProvenance::new(
            "https://ritma.dev/build/v1",
            "https://github.com/actions/runner",
        );
        prov.add_dependency(ResourceDescriptor::new("pkg:cargo/sha2@0.10.0"));
        prov.finish();

        let mut sbom = Sbom::new(SbomFormat::Ritma, "ritma-cli");
        sbom.add_component(SbomComponent::new(ComponentType::Library, "sha2", "0.10.0"));

        let chain = ProvenanceChain::new(prov, sbom);
        let verification = chain.verify();

        // Should be valid (no deployment/runtime to verify)
        assert!(verification.valid);
        assert_ne!(verification.provenance_digest, [0u8; 32]);
        assert_ne!(verification.sbom_digest, [0u8; 32]);

        let cbor = chain.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_provenance_chain_with_deployment() {
        let mut prov = SlsaProvenance::new("build/v1", "builder");
        prov.add_dependency(ResourceDescriptor::new("dep1"));
        prov.finish();

        let mut sbom = Sbom::new(SbomFormat::Ritma, "tool");
        sbom.add_component(SbomComponent::new(ComponentType::Library, "lib", "1.0"));

        let prov_digest = prov.digest();
        let sbom_digest = sbom.digest();

        let deploy = DeploymentRecord::new(prov_digest, sbom_digest, "prod", "deployer");
        let runtime = RuntimeAttestation::new(&deploy.deployment_id, "node1", 1234, [0xee; 32]);

        let chain = ProvenanceChain::new(prov, sbom)
            .with_deployment(deploy)
            .with_runtime(runtime);

        let verification = chain.verify();
        assert!(verification.valid, "Issues: {:?}", verification.issues);
    }
}
