use std::path::{Path, PathBuf};

use chrono::{Datelike, Timelike, Utc};
use thiserror::Error;

use sha2::Digest;

pub mod accounting;
pub mod ai_audit;
pub mod alerting;
pub mod anchors;
pub mod canonical;
pub mod cas;
pub mod cases;
pub mod catalog;
pub mod cctv;
pub mod coldstore;
pub mod cose;
pub mod ctgf;
pub mod dictionary;
pub mod graph;
pub mod hazard;
pub mod investigation;
pub mod k8s_metadata;
pub mod l7_tracing;
pub mod merkle_advanced;
pub mod migration;
pub mod pipeline;
pub mod process_lifecycle;
pub mod proofpack;
pub mod provenance;
pub mod readiness;
pub mod replay;
pub mod rtsl;
pub mod siem_export;
pub mod timejump;
pub mod timestamping;
pub mod tracing_policy;
pub mod triggers;
pub mod tsa;
pub mod verify;
pub mod versioning;
pub use accounting::{
    AccountingAccumulator, ExtendedAccounting, ExtendedAccountingWriter, TopTalker,
};
pub use ai_audit::{
    AiAuditLog, AiDecisionRecord, DecisionExplanation, DecisionInput, DecisionOutput, DecisionType,
    ExplanationType, HumanOverride, InputType, ModelIdentity, ModelType,
};
pub use alerting::{
    builtin_rules, Alert, AlertContainer, AlertFile, AlertHandler, AlertNetwork, AlertProcess,
    AlertSeverity, AlertStatus, ConsoleAlertHandler, Detection, DetectionRule, EventData,
    FileAlertHandler, LogSource, MitreMapping, RuleEngine, Selection, SelectionValue,
};
pub use anchors::{AnchorConfig, AnchorManager, AnchorType, DailyAnchor};
pub use canonical::{CanonicalEventAtom, CaptureMode, EventType, ProofRecord, RunMeta};
pub use cas::{CasStore, ChunkManifest, ChunkRef};
pub use cases::{CaseHeader, CaseManager, CaseStatus, FrozenWindow, FrozenWindowsList};
pub use catalog::{DailyCatalog, DailyCatalogReader, DailyCatalogWriter, WindowSummary};
pub use cctv::{ActorRecord, AppendOnlyEntry, DualTimestamp, KernelEventCoverage, WindowSeal};
pub use coldstore::{ColdStore, PayloadRef, PayloadType};
pub use ctgf::{ConeInstantiation, ConeLibrary, ConePattern, InstantiationBlockWriter};
pub use dictionary::{DictionaryEntry, DictionaryStore};
pub use graph::{Edge, EdgeType, GraphReader, HourlyEdgeWriter};
pub use hazard::{
    HazardEntry, HazardEntryType, HazardLevel, HazardReceipt, HazardRingBuffer, HazardTracer,
    RingBufferHeader, SealReceipt, WitnessAck, WitnessCommitment, WitnessEndpoint, WitnessType,
};
pub use investigation::{
    BlastRadius, EdgeType as InvestigationEdgeType, Finding, FindingSeverity, InvestigationAnchor,
    InvestigationBuilder, InvestigationEdge, InvestigationGraph, InvestigationNode,
    InvestigationReport, InvestigationScope, Neighborhood, NodeType, TimelineEntry,
};
pub use k8s_metadata::{
    parse_container_id_from_cgroup, parse_pod_uid_from_cgroup, ContainerState, ContainerStatus,
    DownwardApiReader, K8sMetadataProvider, K8sTraceContext, NamespaceMetadata, OwnerReference,
    PodMetadata, ServiceMetadata, ServicePort,
};
pub use l7_tracing::{
    HttpMethod, HttpParser, HttpRequest, HttpResponse, HttpTransaction, L7Direction, L7Event,
    L7Protocol, L7TransactionTracker, SensitiveDataDetector,
};
pub use merkle_advanced::{
    CausalWrite, ConsistencyProof, DagCborEncoder, MerkleMountainRange, MerkleTile, MmrProof,
    MultiWriterCoordinator, ProllyChunker, RecordProof, SparseMerkleProof, SparseMerkleTree,
    TiledMerkleTree, VectorClock, TILE_HEIGHT, TILE_WIDTH,
};
pub use migration::{
    ArchiveResult, DiscrepancySeverity, DiscrepancyType, LegacyDisabler, MigrationManager,
    MigrationMode, MigrationPhase, MigrationState, MigrationStatus, ParityDiscrepancy,
    ParityResult, ParityVerifier,
};
pub use pipeline::{HourPipelineStatus, MicroWindowData, PipelineStage, SealingPipeline};
pub use process_lifecycle::{
    signal_name, ProcExitScanner, ProcessExit, ProcessLifecycleEvent, ProcessLifecycleEventType,
    ProcessLifecycleTracker, ProcessNode, ProcessState, ProcessTree,
};
pub use proofpack::{ChainRecord, HourRoot, MicroWindow, ProofPackWriter};
pub use provenance::{
    BuildDefinition, BuildMetadata, BuilderInfo, ComponentType, DeploymentRecord, ProvenanceChain,
    ProvenanceVerification, ResourceDescriptor, RunDetails, RuntimeAttestation, Sbom,
    SbomComponent, SbomFormat, SlsaLevel, SlsaProvenance,
};
pub use readiness::{
    CheckCategory, CheckSeverity, CourtExportPack, CustodyAction, CustodyRecord, EvidenceItem,
    EvidenceType, OverallStatus, ReadinessCheck, ReadinessChecker, ReadinessConfig,
    ReadinessReport,
};
pub use replay::{EntityState, SnapshotDiff, SnapshotStore, StateSnapshot};
pub use rtsl::{CausalRecord, RtslLedger, WindowReceipt};
pub use siem_export::{
    CefExporter, EcsEvent, EcsExporter, LeefExporter, SiemEvent, SiemExportWriter, SiemFormat,
    SiemSeverity, SyslogExporter,
};
pub use timejump::{TimeJumpEntry, TimeJumpIndex, TimeJumpReader, TimeJumpWriter};
pub use timestamping::{
    Accuracy, ChainVerification, ConstraintType, DelegationChain, DelegationConstraint,
    DelegationRecord, DelegationScope, MessageImprint, Principal, PrincipalType,
    TimestampAuthority, TimestampToken, TrustLevel,
};
pub use tracing_policy::{
    builtin_policies, ArgSpec, ArgType, EventContext, FileOperation, FileWatchRule, Filter,
    FilterOperator, K8sSelector, NetworkRule, PolicyAction, PolicyManager, PortSpec, ProcessEvent,
    ProcessRule, Severity, SyscallRule, TracingPolicy,
};
pub use triggers::{TriggerAuditLog, TriggerEvent, TriggerPolicy, TriggerType};
pub use verify::{BundleExporter, OfflineVerifier, VerificationResult};
pub use versioning::{
    ChainedSnapshot, EntityVersion, EventLog, LamportClock, StateEvent, StateEventType,
    StateMachine, VersionVector, VersioningEngine,
};

/// Accounting summary for a day (0.5)
#[derive(Debug, Clone, Default)]
pub struct AccountingSummary {
    pub total_events: u64,
    pub total_bytes_raw: u64,
    pub total_bytes_compressed: u64,
    pub total_bytes_deduped: u64,
}

impl AccountingSummary {
    pub fn compression_ratio(&self) -> f64 {
        if self.total_bytes_raw == 0 {
            return 1.0;
        }
        self.total_bytes_compressed as f64 / self.total_bytes_raw as f64
    }

    pub fn dedupe_ratio(&self) -> f64 {
        if self.total_bytes_raw == 0 {
            return 1.0;
        }
        self.total_bytes_deduped as f64 / self.total_bytes_raw as f64
    }

    pub fn total_savings(&self) -> u64 {
        self.total_bytes_raw
            .saturating_sub(self.total_bytes_compressed)
            .saturating_add(
                self.total_bytes_raw
                    .saturating_sub(self.total_bytes_deduped),
            )
    }
}

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("{0} is required")]
    MissingRequiredEnv(&'static str),
    #[error("invalid {0}: {1}")]
    InvalidEnv(&'static str, String),
}

fn next_micro_id(dir: &Path) -> std::io::Result<u32> {
    let mut max_id: Option<u32> = None;
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    for ent in rd.flatten() {
        if !ent.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = ent.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        if !s.starts_with('w') || !s.ends_with(".cbor") {
            continue;
        }
        let inner = &s[1..s.len() - 5];
        if let Ok(v) = inner.parse::<u32>() {
            max_id = Some(max_id.map(|m| m.max(v)).unwrap_or(v));
        }
    }
    Ok(max_id.map(|m| m + 1).unwrap_or(0))
}

#[derive(Clone, Debug)]
pub struct StorageContract {
    pub node_id: String,
    pub base_dir: PathBuf,
    pub index_db_path: PathBuf,
    pub out_dir: PathBuf,
    pub lock_dir: PathBuf,
    pub lock_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ResolveOpts {
    pub require_node_id: bool,
    pub require_absolute_paths: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Legacy,
    Rtsl,
    Dual,
}

impl Default for ResolveOpts {
    fn default() -> Self {
        Self {
            require_node_id: false,
            require_absolute_paths: false,
        }
    }
}

impl StorageContract {
    fn output_format_from_env() -> OutputFormat {
        match std::env::var("RITMA_OUT_FORMAT") {
            Ok(v) => match v.trim().to_lowercase().as_str() {
                "rtsl" => OutputFormat::Rtsl,
                "dual" => OutputFormat::Dual,
                _ => OutputFormat::Legacy,
            },
            Err(_) => OutputFormat::Legacy,
        }
    }

    pub fn resolve(opts: ResolveOpts) -> Result<Self, ContractError> {
        let node_id = resolve_node_id(opts.require_node_id)?;
        let base_dir = resolve_base_dir();

        let index_db_path = resolve_path_env_or_default(
            &["INDEX_DB_PATH", "RITMA_INDEX_DB_PATH"],
            base_dir.join("index_db.sqlite"),
        )?;

        let out_dir = resolve_path_env_or_default(
            &["RITMA_OUT_DIR", "RITMA_OUT_PATH"],
            base_dir.join("RITMA_OUT"),
        )?;

        let lock_dir = resolve_lock_dir(&base_dir);

        let lock_path = resolve_path_env_or_default(
            &["RITMA_SIDECAR_LOCK_PATH"],
            lock_dir.join(format!(
                "ritma_cctv_tracer_sidecar.{}.lock",
                sanitize_id(&node_id)
            )),
        )?;

        if opts.require_absolute_paths {
            validate_contract_path("INDEX_DB_PATH", &index_db_path, true)?;
            validate_contract_path("RITMA_OUT_DIR", &out_dir, true)?;
            validate_contract_path("RITMA_SIDECAR_LOCK_DIR", &lock_dir, true)?;
            validate_contract_path("RITMA_SIDECAR_LOCK_PATH", &lock_path, true)?;
        }

        Ok(Self {
            node_id,
            base_dir,
            index_db_path,
            out_dir,
            lock_dir,
            lock_path,
        })
    }

    pub fn tracer_lock_path(&self) -> PathBuf {
        self.lock_path.clone()
    }

    pub fn orchestrator_lock_path(&self) -> PathBuf {
        let id = sanitize_id(&self.node_id);
        self.lock_dir
            .join(format!("ritma_bar_orchestrator.{id}.lock"))
    }

    pub fn ensure_base_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.base_dir)
    }

    pub fn ensure_out_layout(&self) -> std::io::Result<()> {
        let root = &self.out_dir;
        std::fs::create_dir_all(root)?;
        for rel in [
            "_meta",
            "_meta/keys",
            "_meta/schema",
            "_meta/health",
            "catalog",
            "windows",
            "graph/dict",
            "graph/edges",
            "ctgf/cones/v0001",
            "cas/b3",
            "accounting",
            "cases",
            "exports",
            "ledger/v2",
            "ledger/v2/shards",
            "ledger/v2/chain",
            "ledger/v2/_meta",
            "ledger/v2/_meta/keys",
            "ledger/v2/_meta/schema",
        ] {
            std::fs::create_dir_all(root.join(rel))?;
        }

        // Initialize all _meta/ artifacts (2.1)
        self.ensure_meta_artifacts()?;
        Ok(())
    }

    pub fn write_window_output(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
        total_events: u64,
        leaf_hashes: &[[u8; 32]],
    ) -> std::io::Result<()> {
        let fmt = Self::output_format_from_env();
        if env_truthy("RITMA_OUT_ENFORCE_RTSL") && fmt != OutputFormat::Rtsl {
            return Err(std::io::Error::other(
                "RTSL output is enforced (RITMA_OUT_ENFORCE_RTSL=1); set RITMA_OUT_FORMAT=rtsl",
            ));
        }

        match fmt {
            OutputFormat::Legacy => {
                let _ = self.write_micro_window_proof(
                    namespace_id,
                    start_ts,
                    end_ts,
                    total_events,
                    leaf_hashes,
                )?;
                Ok(())
            }
            OutputFormat::Rtsl => {
                let _ = crate::rtsl::write_window_as_rtsl_record(
                    self,
                    namespace_id,
                    start_ts,
                    end_ts,
                    total_events,
                    leaf_hashes,
                )?;
                Ok(())
            }
            OutputFormat::Dual => {
                let legacy_micro_path = self.write_micro_window_proof(
                    namespace_id,
                    start_ts,
                    end_ts,
                    total_events,
                    leaf_hashes,
                )?;
                let _rtsl_segment_path = crate::rtsl::write_window_as_rtsl_record(
                    self,
                    namespace_id,
                    start_ts,
                    end_ts,
                    total_events,
                    leaf_hashes,
                )?;

                if env_truthy("RITMA_OUT_PARITY_VERIFY") {
                    let expected_root = merkle_root_sha256(leaf_hashes);
                    let bytes = std::fs::read(&legacy_micro_path)?;
                    let v = ciborium::from_reader::<ciborium::value::Value, _>(&bytes[..])
                        .map_err(std::io::Error::other)?;

                    let Some(micro_root_hex) = parse_micro_root_hex(&v) else {
                        return Err(std::io::Error::other(format!(
                            "parity verify failed: could not parse micro_root from {}",
                            legacy_micro_path.display()
                        )));
                    };
                    let Some(legacy_root) = decode_32(&micro_root_hex) else {
                        return Err(std::io::Error::other(format!(
                            "parity verify failed: invalid micro_root hex in {}",
                            legacy_micro_path.display()
                        )));
                    };
                    if legacy_root != expected_root {
                        return Err(std::io::Error::other(
                            "parity verify failed: legacy micro_root != expected merkle_root_sha256(leaves)",
                        ));
                    }
                }

                Ok(())
            }
        }
    }

    fn append_daily_catalog_stub(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
        total_events: u64,
    ) -> std::io::Result<PathBuf> {
        let dt = chrono::DateTime::<Utc>::from_timestamp(start_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap());

        let day_dir = self
            .out_dir
            .join("catalog")
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()));
        std::fs::create_dir_all(&day_dir)?;
        let p = day_dir.join("day.cbor.zst");

        // Minimal v0 catalog entry tuple:
        // ["ritma-catalog@0.1", namespace_id, node_id, start_ts, end_ts, total_events]
        let entry = (
            "ritma-catalog@0.1",
            namespace_id,
            self.node_id.as_str(),
            start_ts,
            end_ts,
            total_events,
        );

        let bytes = {
            let mut buf: Vec<u8> = Vec::new();
            ciborium::into_writer(&entry, &mut buf).map_err(std::io::Error::other)?;
            buf
        };
        let compressed = zstd::encode_all(&bytes[..], 0).map_err(std::io::Error::other)?;

        // Best-effort append style: newline-separated compressed CBOR records isn't ideal.
        // For v0 we keep it simple: append framed records with a u32 length prefix.
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)?;
        let len = compressed.len() as u32;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&compressed)?;
        Ok(p)
    }

    fn cases_for_range(&self, start_ts: i64, end_ts: i64) -> Vec<String> {
        let cases_dir = self.out_dir.join("cases");
        let rd = match std::fs::read_dir(&cases_dir) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let mut case_ids: Vec<String> = Vec::new();
        for entry in rd.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let manifest = entry.path().join("manifest.cbor");
            let Ok(data) = std::fs::read(&manifest) else {
                continue;
            };
            let Ok(v) = ciborium::from_reader::<ciborium::value::Value, _>(&data[..]) else {
                continue;
            };
            if self.manifest_covers_window(&v, start_ts, end_ts) {
                if let Some(name) = entry.file_name().to_str() {
                    case_ids.push(name.to_string());
                }
            }
        }
        case_ids
    }

    pub fn write_micro_window_stub(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
        total_events: u64,
    ) -> std::io::Result<PathBuf> {
        self.ensure_out_layout()?;

        let hour_dir = self.hour_partition_dir(start_ts);
        std::fs::create_dir_all(hour_dir.join("micro"))?;
        std::fs::create_dir_all(hour_dir.join("proofs"))?;
        std::fs::create_dir_all(hour_dir.join("blocks"))?;
        std::fs::create_dir_all(hour_dir.join("index"))?;

        self.ensure_hour_placeholders(&hour_dir, start_ts)?;

        let next_id = next_micro_id(&hour_dir.join("micro"))?;
        let name = format!("w{next_id:03}");
        let micro_path = hour_dir.join("micro").join(format!("{name}.cbor"));
        let sig_path = hour_dir.join("micro").join(format!("{name}.sig"));

        let f = std::fs::File::create(&micro_path)?;
        let tuple = (
            "ritma-micro@0.1",
            namespace_id,
            self.node_id.as_str(),
            start_ts,
            end_ts,
            total_events,
            "cone_lib=v0001",
        );
        ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;

        if !sig_path.exists() {
            let _ = std::fs::File::create(&sig_path)?;
        }

        let _ = self.append_daily_catalog_stub(namespace_id, start_ts, end_ts, total_events);

        Ok(micro_path)
    }

    pub fn write_micro_window_proof(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
        total_events: u64,
        leaf_hashes: &[[u8; 32]],
    ) -> std::io::Result<PathBuf> {
        self.ensure_out_layout()?;

        let hour_dir = self.hour_partition_dir(start_ts);
        std::fs::create_dir_all(hour_dir.join("micro"))?;
        std::fs::create_dir_all(hour_dir.join("proofs"))?;
        std::fs::create_dir_all(hour_dir.join("blocks"))?;
        std::fs::create_dir_all(hour_dir.join("index"))?;

        let _ = self.ensure_hour_placeholders(&hour_dir, start_ts);

        let micro_root = merkle_root_sha256(leaf_hashes);
        let next_id = next_micro_id(&hour_dir.join("micro"))?;
        let name = format!("w{next_id:03}");
        let micro_path = hour_dir.join("micro").join(format!("{name}.cbor"));
        let sig_path = hour_dir.join("micro").join(format!("{name}.sig"));

        let f = std::fs::File::create(&micro_path)?;
        let tuple = (
            "ritma-micro@0.2",
            namespace_id,
            self.node_id.as_str(),
            start_ts,
            end_ts,
            total_events,
            leaf_hashes.len() as u64,
            hex::encode(micro_root),
            "cone_lib=v0001",
        );
        ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;

        let leaves_path = hour_dir
            .join("micro")
            .join(format!("{name}.leaves.cbor.zst"));
        let leaf_hex: Vec<String> = leaf_hashes.iter().map(hex::encode).collect();
        let leaves_tuple = (
            "ritma-micro-leaves@0.1",
            namespace_id,
            self.node_id.as_str(),
            start_ts,
            end_ts,
            name.as_str(),
            leaf_hex,
        );
        let mut leaves_buf: Vec<u8> = Vec::new();
        ciborium::into_writer(&leaves_tuple, &mut leaves_buf).map_err(std::io::Error::other)?;
        let leaves_compressed =
            zstd::encode_all(&leaves_buf[..], 0).map_err(std::io::Error::other)?;
        std::fs::write(&leaves_path, leaves_compressed)?;

        self.write_sig_file(&sig_path, "ritma-micro-sig@0.1", &micro_root)?;

        let (micro_roots, hour_root) = self.compute_hour_root_from_micro(&hour_dir)?;
        let chain_hash =
            self.write_hour_root_files(start_ts, &hour_dir, &hour_root, &micro_roots)?;

        let _ = self.append_timejump_index(
            &hour_dir,
            namespace_id,
            start_ts,
            end_ts,
            &name,
            &micro_root,
            &hour_root,
            &chain_hash,
        );

        let _ = self.append_daily_catalog_entry(
            namespace_id,
            start_ts,
            end_ts,
            total_events,
            leaf_hashes.len() as u64,
            &name,
            &micro_root,
            &hour_root,
            &chain_hash,
        );
        Ok(micro_path)
    }

    fn append_timejump_index(
        &self,
        hour_dir: &Path,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
        micro_name: &str,
        micro_root: &[u8; 32],
        hour_root: &[u8; 32],
        chain_hash: &[u8; 32],
    ) -> std::io::Result<PathBuf> {
        let p = hour_dir.join("index").join("timejump.cbor");
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let entry = (
            "ritma-timejump@0.2",
            namespace_id,
            self.node_id.as_str(),
            start_ts,
            end_ts,
            micro_name,
            hex::encode(micro_root),
            hex::encode(hour_root),
            hex::encode(chain_hash),
        );

        let bytes = {
            let mut buf: Vec<u8> = Vec::new();
            ciborium::into_writer(&entry, &mut buf).map_err(std::io::Error::other)?;
            buf
        };

        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)?;
        let len = bytes.len() as u32;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&bytes)?;
        Ok(p)
    }

    fn append_daily_catalog_entry(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
        total_events: u64,
        leaf_count: u64,
        micro_name: &str,
        micro_root: &[u8; 32],
        hour_root: &[u8; 32],
        chain_hash: &[u8; 32],
    ) -> std::io::Result<PathBuf> {
        let dt = chrono::DateTime::<Utc>::from_timestamp(start_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap());

        let day_dir = self
            .out_dir
            .join("catalog")
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()));
        std::fs::create_dir_all(&day_dir)?;
        let p = day_dir.join("day.cbor.zst");

        let mut case_ids = self.cases_for_range(start_ts, end_ts);
        case_ids.sort();
        case_ids.dedup();
        let retention_lock = !case_ids.is_empty();

        let entry = (
            "ritma-catalog@0.3",
            namespace_id,
            self.node_id.as_str(),
            start_ts,
            end_ts,
            total_events,
            leaf_count,
            micro_name,
            hex::encode(micro_root),
            hex::encode(hour_root),
            hex::encode(chain_hash),
            retention_lock,
            case_ids,
        );

        let bytes = {
            let mut buf: Vec<u8> = Vec::new();
            ciborium::into_writer(&entry, &mut buf).map_err(std::io::Error::other)?;
            buf
        };
        let compressed = zstd::encode_all(&bytes[..], 0).map_err(std::io::Error::other)?;

        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)?;
        let len = compressed.len() as u32;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&compressed)?;
        Ok(p)
    }

    fn ensure_store_meta_file(&self) -> std::io::Result<()> {
        let p = self.out_dir.join("_meta").join("store.cbor");
        if p.exists() {
            return Ok(());
        }
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = std::fs::File::create(p)?;
        let tuple = (
            "ritma-out@0.1",
            "ctgf-proofpack",
            self.node_id.as_str(),
            self.base_dir.display().to_string(),
            self.out_dir.display().to_string(),
        );
        ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)
    }

    /// Write _meta/keys/pubkeys.cbor with public key metadata (2.1)
    pub fn ensure_keys_meta(&self) -> std::io::Result<()> {
        let keys_dir = self.out_dir.join("_meta").join("keys");
        std::fs::create_dir_all(&keys_dir)?;

        let pubkeys_path = keys_dir.join("pubkeys.cbor");
        if pubkeys_path.exists() {
            return Ok(());
        }

        // Collect public keys from keystore if available
        let keys: Vec<(String, String, String, Option<String>)> =
            match node_keystore::NodeKeystore::from_env() {
                Ok(ks) => ks
                    .list_metadata()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|m| {
                        (
                            m.key_id,
                            m.key_hash,
                            m.label.unwrap_or_default(),
                            m.public_key_hex,
                        )
                    })
                    .collect(),
                Err(_) => vec![],
            };

        let f = std::fs::File::create(&pubkeys_path)?;
        let tuple = (
            "ritma-pubkeys@0.2",
            self.node_id.as_str(),
            chrono::Utc::now().timestamp(),
            keys,
        );
        ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;

        // Initialize empty key rotation log
        let rotation_log = keys_dir.join("key_rotation_log.cbor.zst");
        if !rotation_log.exists() {
            let empty: Vec<(String, i64, String)> = vec![];
            let mut buf: Vec<u8> = Vec::new();
            ciborium::into_writer(&("ritma-key-rotation@0.1", &empty), &mut buf)
                .map_err(std::io::Error::other)?;
            let compressed = zstd::encode_all(&buf[..], 0).map_err(std::io::Error::other)?;
            std::fs::write(&rotation_log, compressed)?;
        }

        Ok(())
    }

    /// Write _meta/schema/*.cbor with schema definitions (2.1)
    pub fn ensure_schema_meta(&self) -> std::io::Result<()> {
        let schema_dir = self.out_dir.join("_meta").join("schema");
        std::fs::create_dir_all(&schema_dir)?;

        // Event schema v1: defines canonical event atom tuple layout
        let event_schema = schema_dir.join("event_schema_v1.cbor");
        if !event_schema.exists() {
            let f = std::fs::File::create(&event_schema)?;
            let tuple = (
                "ritma-event-schema@0.1",
                1u32, // version
                // Canonical event atom tuple layout (positional):
                // [0] tΔ: i64 (microseconds since window start)
                // [1] etype: u16 (event type enum)
                // [2] actor: u64 (actor dictionary ID)
                // [3] object: u64 (object dictionary ID)
                // [4] flags_class: u32 (packed flags + classification)
                // [5] arg_hash: Option<[u8;32]> (argument hash, null if none)
                // [6] payload_ref: Option<String> (CAS reference, null if thin)
                vec![
                    ("tΔ", "i64", "microseconds since window start"),
                    ("etype", "u16", "event type enum"),
                    ("actor", "u64", "actor dictionary ID"),
                    ("object", "u64", "object dictionary ID"),
                    ("flags_class", "u32", "packed flags + classification"),
                    ("arg_hash", "Option<[u8;32]>", "argument hash"),
                    (
                        "payload_ref",
                        "Option<String>",
                        "CAS reference for thick/full",
                    ),
                ],
            );
            ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;
        }

        // Cone schema v1: defines CTGF cone pattern representation
        let cone_schema = schema_dir.join("cone_schema_v1.cbor");
        if !cone_schema.exists() {
            let f = std::fs::File::create(&cone_schema)?;
            let tuple = (
                "ritma-cone-schema@0.1",
                1u32,
                vec![
                    ("cone_id", "u32", "unique cone identifier"),
                    ("pattern", "Vec<u8>", "compressed pattern bytes"),
                    ("placeholders", "Vec<String>", "placeholder names"),
                    ("version", "u16", "cone version"),
                ],
            );
            ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;
        }

        // Proof schema v1: defines proof ledger record format
        let proof_schema = schema_dir.join("proof_schema_v1.cbor");
        if !proof_schema.exists() {
            let f = std::fs::File::create(&proof_schema)?;
            let tuple = (
                "ritma-proof-schema@0.1",
                1u32,
                vec![
                    ("merkle_root", "[u8;32]", "Merkle root of event hashes"),
                    ("prev_root", "[u8;32]", "previous hour root (chain)"),
                    ("chain_hash", "[u8;32]", "hash(prev_root || merkle_root)"),
                    ("signature", "Option<Vec<u8>>", "optional signature"),
                    ("run_meta", "RunMeta", "run identity metadata"),
                ],
                // RunMeta sub-schema
                vec![
                    ("host_id", "String", "host/node identifier"),
                    ("boot_id", "Option<String>", "boot identifier"),
                    ("sensor_version", "String", "tracer version"),
                    ("config_digest", "[u8;32]", "hash of active config"),
                ],
            );
            ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;
        }

        Ok(())
    }

    /// Write _meta/health/*.cbor with health/stats artifacts (2.1)
    pub fn ensure_health_meta(&self) -> std::io::Result<()> {
        let health_dir = self.out_dir.join("_meta").join("health");
        std::fs::create_dir_all(&health_dir)?;

        // Last compaction record
        let compaction = health_dir.join("last_compaction.cbor");
        if !compaction.exists() {
            let f = std::fs::File::create(&compaction)?;
            let tuple = (
                "ritma-compaction@0.1",
                0i64, // last_compaction_ts (0 = never)
                0u64, // bytes_before
                0u64, // bytes_after
                0u64, // records_compacted
            );
            ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;
        }

        // Rolling 7-day stats
        let stats = health_dir.join("stats_rolling_7d.cbor.zst");
        if !stats.exists() {
            let empty_stats: Vec<(i64, u64, u64, u64)> = vec![]; // (day_ts, events, bytes, windows)
            let mut buf: Vec<u8> = Vec::new();
            ciborium::into_writer(&("ritma-stats@0.1", &empty_stats), &mut buf)
                .map_err(std::io::Error::other)?;
            let compressed = zstd::encode_all(&buf[..], 0).map_err(std::io::Error::other)?;
            std::fs::write(&stats, compressed)?;
        }

        Ok(())
    }

    /// Initialize all _meta/ artifacts (2.1 complete)
    pub fn ensure_meta_artifacts(&self) -> std::io::Result<()> {
        self.ensure_store_meta_file()?;
        self.ensure_keys_meta()?;
        self.ensure_schema_meta()?;
        self.ensure_health_meta()?;
        Ok(())
    }

    // =========================================================================
    // Case Freezing (0.5) - blocks retention deletion for frozen cases
    // =========================================================================

    /// Create a case freeze manifest that protects windows from retention deletion
    pub fn freeze_case(
        &self,
        case_id: &str,
        window_refs: &[(i64, i64)], // (start_ts, end_ts) pairs
        reason: &str,
    ) -> std::io::Result<PathBuf> {
        let case_dir = self.out_dir.join("cases").join(case_id);
        std::fs::create_dir_all(&case_dir)?;

        let manifest_path = case_dir.join("manifest.cbor");
        let f = std::fs::File::create(&manifest_path)?;
        let tuple = (
            "ritma-case-manifest@0.1",
            case_id,
            self.node_id.as_str(),
            chrono::Utc::now().timestamp(),
            reason,
            window_refs,
            "frozen", // status
        );
        ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;

        // Initialize access log
        let access_log = case_dir.join("access_log.cbor.zst");
        if !access_log.exists() {
            let empty: Vec<(i64, String, String)> = vec![]; // (ts, actor, action)
            let mut buf: Vec<u8> = Vec::new();
            ciborium::into_writer(&("ritma-access-log@0.1", &empty), &mut buf)
                .map_err(std::io::Error::other)?;
            let compressed = zstd::encode_all(&buf[..], 0).map_err(std::io::Error::other)?;
            std::fs::write(&access_log, compressed)?;
        }

        Ok(manifest_path)
    }

    /// Check if a window timestamp range is frozen by any case
    pub fn is_window_frozen(&self, start_ts: i64, end_ts: i64) -> bool {
        let cases_dir = self.out_dir.join("cases");
        let rd = match std::fs::read_dir(&cases_dir) {
            Ok(r) => r,
            Err(_) => return false,
        };

        for entry in rd.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let manifest = entry.path().join("manifest.cbor");
            if let Ok(data) = std::fs::read(&manifest) {
                if let Ok(v) = ciborium::from_reader::<ciborium::value::Value, _>(&data[..]) {
                    if self.manifest_covers_window(&v, start_ts, end_ts) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn manifest_covers_window(
        &self,
        v: &ciborium::value::Value,
        start_ts: i64,
        end_ts: i64,
    ) -> bool {
        let ciborium::value::Value::Array(arr) = v else {
            return false;
        };
        // tuple[5] is window_refs: Vec<(i64, i64)>
        let Some(ciborium::value::Value::Array(refs)) = arr.get(5) else {
            return false;
        };
        for r in refs {
            let ciborium::value::Value::Array(pair) = r else {
                continue;
            };
            let (
                Some(ciborium::value::Value::Integer(ws)),
                Some(ciborium::value::Value::Integer(we)),
            ) = (pair.get(0), pair.get(1))
            else {
                continue;
            };
            let ws: i64 = (*ws).try_into().unwrap_or(0);
            let we: i64 = (*we).try_into().unwrap_or(0);
            // Check overlap
            if start_ts < we && end_ts > ws {
                return true;
            }
        }
        false
    }

    /// List all frozen case IDs
    pub fn list_frozen_cases(&self) -> std::io::Result<Vec<String>> {
        let cases_dir = self.out_dir.join("cases");
        let mut cases = Vec::new();
        let rd = match std::fs::read_dir(&cases_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(cases),
            Err(e) => return Err(e),
        };
        for entry in rd.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    if entry.path().join("manifest.cbor").exists() {
                        cases.push(name.to_string());
                    }
                }
            }
        }
        Ok(cases)
    }

    // =========================================================================
    // Accounting Ledger (0.5) - bytes, compression, dedupe, top talkers
    // =========================================================================

    /// Record accounting entry for a window
    pub fn record_accounting(
        &self,
        day_ts: i64,
        events: u64,
        bytes_raw: u64,
        bytes_compressed: u64,
        bytes_deduped: u64,
    ) -> std::io::Result<PathBuf> {
        let dt = chrono::DateTime::<Utc>::from_timestamp(day_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap());

        let day_dir = self
            .out_dir
            .join("accounting")
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()));
        std::fs::create_dir_all(&day_dir)?;

        let p = day_dir.join("account.cbor.zst");

        let entry = (
            "ritma-accounting@0.1",
            self.node_id.as_str(),
            day_ts,
            events,
            bytes_raw,
            bytes_compressed,
            bytes_deduped,
            bytes_raw.saturating_sub(bytes_compressed), // savings
        );

        let bytes = {
            let mut buf: Vec<u8> = Vec::new();
            ciborium::into_writer(&entry, &mut buf).map_err(std::io::Error::other)?;
            buf
        };
        let compressed = zstd::encode_all(&bytes[..], 0).map_err(std::io::Error::other)?;

        // Append framed record
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)?;
        let len = compressed.len() as u32;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&compressed)?;

        Ok(p)
    }

    /// Get accounting summary for a day
    pub fn get_accounting_summary(&self, day_ts: i64) -> std::io::Result<AccountingSummary> {
        let dt = chrono::DateTime::<Utc>::from_timestamp(day_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap());

        let p = self
            .out_dir
            .join("accounting")
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()))
            .join("account.cbor.zst");

        if !p.exists() {
            return Ok(AccountingSummary::default());
        }

        let data = std::fs::read(&p)?;
        let mut summary = AccountingSummary::default();
        let mut offset = 0;

        while offset + 4 <= data.len() {
            let len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;
            if offset + len > data.len() {
                break;
            }
            let chunk = &data[offset..offset + len];
            offset += len;

            if let Ok(decompressed) = zstd::decode_all(chunk) {
                if let Ok(v) = ciborium::from_reader::<ciborium::value::Value, _>(&decompressed[..])
                {
                    if let Some(entry) = parse_accounting_entry(&v) {
                        summary.total_events += entry.0;
                        summary.total_bytes_raw += entry.1;
                        summary.total_bytes_compressed += entry.2;
                        summary.total_bytes_deduped += entry.3;
                    }
                }
            }
        }

        Ok(summary)
    }

    fn hour_partition_dir(&self, ts: i64) -> PathBuf {
        let dt = chrono::DateTime::<Utc>::from_timestamp(ts, 0)
            .unwrap_or_else(|| chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap());
        self.out_dir
            .join("windows")
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()))
            .join(format!("{:02}", dt.hour()))
    }

    fn ensure_hour_placeholders(&self, hour_dir: &Path, start_ts: i64) -> std::io::Result<()> {
        let header = hour_dir.join("hour_header.cbor");
        if !header.exists() {
            let f = std::fs::File::create(&header)?;
            let tuple = (
                "ritma-hour@0.1",
                self.node_id.as_str(),
                start_ts,
                "cone_lib=v0001",
            );
            ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;
        }

        for (rel, tuple) in [
            (
                "proofs/hour_root.cbor",
                ("ritma-hour-root@0.1", self.node_id.as_str()),
            ),
            (
                "proofs/chain.cbor",
                ("ritma-chain@0.1", "prev_root=GENESIS"),
            ),
        ] {
            let p = hour_dir.join(rel);
            if p.exists() {
                continue;
            }
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let f = std::fs::File::create(&p)?;
            ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;
        }

        let sig = hour_dir.join("proofs").join("hour_root.sig");
        if !sig.exists() {
            let _ = std::fs::File::create(sig)?;
        }

        Ok(())
    }

    fn compute_hour_root_from_micro(
        &self,
        hour_dir: &Path,
    ) -> std::io::Result<(Vec<[u8; 32]>, [u8; 32])> {
        let micro_dir = hour_dir.join("micro");
        let mut entries: Vec<(String, PathBuf)> = Vec::new();
        let rd = match std::fs::read_dir(&micro_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Vec::new(), merkle_root_sha256(&[])))
            }
            Err(e) => return Err(e),
        };
        for ent in rd.flatten() {
            if !ent.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let Some(name) = ent.file_name().to_str().map(|s| s.to_string()) else {
                continue;
            };
            if !name.ends_with(".cbor") {
                continue;
            }
            entries.push((name, ent.path()));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut roots: Vec<[u8; 32]> = Vec::new();
        for (_name, path) in entries {
            let data = std::fs::read(path)?;
            let Ok(v) = ciborium::from_reader::<ciborium::value::Value, _>(&data[..]) else {
                continue;
            };
            let Some(root_hex) = parse_micro_root_hex(&v) else {
                continue;
            };
            let Some(root) = decode_32(&root_hex) else {
                continue;
            };
            roots.push(root);
        }

        let hour_root = merkle_root_sha256(&roots);
        Ok((roots, hour_root))
    }

    fn write_hour_root_files(
        &self,
        start_ts: i64,
        hour_dir: &Path,
        hour_root: &[u8; 32],
        micro_roots: &[[u8; 32]],
    ) -> std::io::Result<[u8; 32]> {
        let proofs = hour_dir.join("proofs");
        std::fs::create_dir_all(&proofs)?;

        let p = proofs.join("hour_root.cbor");
        let f = std::fs::File::create(&p)?;
        let micro_roots_hex: Vec<String> = micro_roots.iter().map(hex::encode).collect();
        let tuple = (
            "ritma-hour-root@0.2",
            self.node_id.as_str(),
            start_ts,
            hex::encode(hour_root),
            micro_roots_hex,
        );
        ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;

        let sig = proofs.join("hour_root.sig");
        self.write_sig_file(&sig, "ritma-hour-root-sig@0.1", hour_root)?;

        let prev = self.find_prev_hour_root_by_ts(start_ts).unwrap_or_else(|| {
            use sha2::Digest;
            let h = sha2::Sha256::digest(b"GENESIS");
            hex::encode(h)
        });
        let chain_hash = compute_chain_hash(&prev, hour_root);

        let chain = proofs.join("chain.cbor");
        let f = std::fs::File::create(&chain)?;
        let tuple = (
            "ritma-chain@0.3",
            self.node_id.as_str(),
            start_ts,
            prev,
            hex::encode(hour_root),
            hex::encode(chain_hash),
        );
        ciborium::into_writer(&tuple, f).map_err(std::io::Error::other)?;

        let chain_sig = proofs.join("chain.sig");
        self.write_sig_file(&chain_sig, "ritma-chain-sig@0.1", &chain_hash)?;

        let require_tpm = env_truthy("RITMA_OUT_REQUIRE_TPM");
        if let Ok(mut attestor) = node_keystore::TpmAttestor::from_env() {
            match attestor.attest(&chain_hash) {
                Ok(res) if res.success => {
                    if let Some(quote) = res.quote {
                        let binding = node_keystore::AttestationBinding::from_quote(&quote);
                        let q_path = proofs.join("tpm_quote.cbor");
                        let b_path = proofs.join("tpm_binding.cbor");

                        let qf = std::fs::File::create(q_path)?;
                        ciborium::into_writer(&quote, qf).map_err(std::io::Error::other)?;

                        let bf = std::fs::File::create(b_path)?;
                        let b_tuple = (
                            "ritma-tpm-binding@0.1",
                            binding.quote_hash,
                            binding.pcr_digest,
                            binding.hardware_tpm,
                            binding.timestamp,
                            binding.node_id,
                        );
                        ciborium::into_writer(&b_tuple, bf).map_err(std::io::Error::other)?;
                    } else if require_tpm {
                        return Err(std::io::Error::other("TPM attestation missing quote"));
                    }
                }
                Ok(_) if require_tpm => {
                    return Err(std::io::Error::other("TPM attestation failed"));
                }
                Err(e) if require_tpm => {
                    return Err(std::io::Error::other(format!("TPM attestation error: {e}")));
                }
                _ => {}
            }
        } else if require_tpm {
            return Err(std::io::Error::other("TPM attestor unavailable"));
        }

        Ok(chain_hash)
    }

    fn find_prev_hour_root_by_ts(&self, ts: i64) -> Option<String> {
        let prev_ts = ts - 3600;
        let prev_dir = self.hour_partition_dir(prev_ts);
        let p = prev_dir.join("proofs").join("hour_root.cbor");
        let Ok(data) = std::fs::read(p) else {
            return None;
        };
        let Ok(v) = ciborium::from_reader::<ciborium::value::Value, _>(&data[..]) else {
            return None;
        };
        parse_hour_root_hex(&v)
    }

    fn write_sig_file(
        &self,
        path: &Path,
        sig_tag: &str,
        payload32: &[u8; 32],
    ) -> std::io::Result<()> {
        let require = env_truthy("RITMA_OUT_REQUIRE_SIGNATURE");
        let key_id = env_nonempty("RITMA_SIGNING_KEY_ID").unwrap_or_else(|| "default".to_string());

        let mut msg: Vec<u8> = Vec::new();
        let tuple = (
            "ritma-signed@0.1",
            sig_tag,
            self.node_id.as_str(),
            hex::encode(payload32),
        );
        ciborium::into_writer(&tuple, &mut msg).map_err(std::io::Error::other)?;

        let (alg, sig_hex) = match node_keystore::NodeKeystore::from_env() {
            Ok(ks) => match ks.key_for_signing(&key_id) {
                Ok(k) => match ks.sign_bytes(&k.key_id, &msg) {
                    Ok(sig) => (k.key_type.clone(), sig),
                    Err(e) => {
                        if require {
                            return Err(std::io::Error::other(format!(
                                "keystore sign failed: {e}"
                            )));
                        }
                        ("none".to_string(), String::new())
                    }
                },
                Err(e) => {
                    if require {
                        return Err(std::io::Error::other(format!("keystore key error: {e}")));
                    }
                    ("none".to_string(), String::new())
                }
            },
            Err(e) => {
                if require {
                    return Err(std::io::Error::other(format!("keystore unavailable: {e}")));
                }
                ("none".to_string(), String::new())
            }
        };

        let f = std::fs::File::create(path)?;
        let out = (
            "ritma-sig@0.1",
            key_id,
            alg,
            hex::encode(payload32),
            sig_hex,
        );
        ciborium::into_writer(&out, f).map_err(std::io::Error::other)
    }

    pub fn resolve_best_effort() -> Self {
        Self::resolve(ResolveOpts::default()).unwrap_or_else(|_| {
            let node_id = "local".to_string();
            let base_dir = PathBuf::from("./.ritma/data");
            let index_db_path = base_dir.join("index_db.sqlite");
            let out_dir = base_dir.join("RITMA_OUT");
            let lock_dir = PathBuf::from("/tmp/ritma/locks");
            let lock_path = lock_dir.join("ritma_cctv_tracer_sidecar.local.lock");
            Self {
                node_id,
                base_dir,
                index_db_path,
                out_dir,
                lock_dir,
                lock_path,
            }
        })
    }

    pub fn resolve_cctv() -> Result<Self, ContractError> {
        let allow_fallback = env_truthy("RITMA_ALLOW_NODE_ID_FALLBACK");
        Self::resolve(ResolveOpts {
            require_node_id: !allow_fallback,
            require_absolute_paths: true,
        })
    }
}

fn validate_contract_path(
    name: &'static str,
    p: &Path,
    require_absolute: bool,
) -> Result<(), ContractError> {
    let s = p.to_string_lossy();
    if s.len() > 4096 {
        return Err(ContractError::InvalidEnv(name, "too long".to_string()));
    }
    if s.contains('\0') {
        return Err(ContractError::InvalidEnv(
            name,
            "must not contain NUL".to_string(),
        ));
    }
    if require_absolute && !p.is_absolute() {
        return Err(ContractError::InvalidEnv(
            name,
            "must be an absolute path".to_string(),
        ));
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ContractError::InvalidEnv(
            name,
            "must not contain '..'".to_string(),
        ));
    }
    Ok(())
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

fn decode_32(hex_s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn compute_chain_hash(prev_hour_root: &str, hour_root: &[u8; 32]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(b"ritma-chain-hash@0.1");

    let prev = decode_32(prev_hour_root).unwrap_or_else(|| {
        use sha2::Digest;
        sha2::Sha256::digest(prev_hour_root.as_bytes()).into()
    });
    h.update(prev);
    h.update(hour_root);
    h.finalize().into()
}

fn parse_micro_root_hex(v: &ciborium::value::Value) -> Option<String> {
    let ciborium::value::Value::Array(arr) = v else {
        return None;
    };
    if arr.len() < 8 {
        return None;
    }
    let Some(ciborium::value::Value::Text(tag)) = arr.get(0) else {
        return None;
    };
    if tag != "ritma-micro@0.2" {
        return None;
    }
    match arr.get(7) {
        Some(ciborium::value::Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn parse_hour_root_hex(v: &ciborium::value::Value) -> Option<String> {
    let ciborium::value::Value::Array(arr) = v else {
        return None;
    };
    if arr.len() < 4 {
        return None;
    }
    let Some(ciborium::value::Value::Text(tag)) = arr.get(0) else {
        return None;
    };
    if tag != "ritma-hour-root@0.2" {
        return None;
    }
    match arr.get(3) {
        Some(ciborium::value::Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn parse_accounting_entry(v: &ciborium::value::Value) -> Option<(u64, u64, u64, u64)> {
    let ciborium::value::Value::Array(arr) = v else {
        return None;
    };
    if arr.len() < 7 {
        return None;
    }
    let Some(ciborium::value::Value::Text(tag)) = arr.get(0) else {
        return None;
    };
    if !tag.starts_with("ritma-accounting@") {
        return None;
    }
    // tuple: (tag, node_id, day_ts, events, bytes_raw, bytes_compressed, bytes_deduped, savings)
    let events = match arr.get(3) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };
    let bytes_raw = match arr.get(4) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };
    let bytes_compressed = match arr.get(5) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };
    let bytes_deduped = match arr.get(6) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };
    Some((events, bytes_raw, bytes_compressed, bytes_deduped))
}

pub(crate) fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        let mut h = sha2::Sha256::new();
        h.update(b"ritma-merkle-empty@0.1");
        return h.finalize().into();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            let mut h = sha2::Sha256::new();
            h.update(b"ritma-merkle-node@0.1");
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());
            i += 2;
        }
        level = next;
    }
    level[0]
}

fn resolve_path_env_or_default(
    names: &[&'static str],
    default: PathBuf,
) -> Result<PathBuf, ContractError> {
    for n in names {
        if let Some(v) = env_nonempty(n) {
            if v.len() > 4096 {
                return Err(ContractError::InvalidEnv(n, "too long".to_string()));
            }
            if v.contains('\0') {
                return Err(ContractError::InvalidEnv(
                    n,
                    "must not contain NUL".to_string(),
                ));
            }
            return Ok(PathBuf::from(v));
        }
    }
    Ok(default)
}

fn resolve_node_id(require_node_id: bool) -> Result<String, ContractError> {
    if let Some(v) = env_nonempty("RITMA_NODE_ID").or_else(|| env_nonempty("RITMA_HOST_ID")) {
        return Ok(v);
    }

    if require_node_id {
        return Err(ContractError::MissingRequiredEnv("RITMA_NODE_ID"));
    }

    if let Some(v) = read_trimmed("/etc/machine-id") {
        return Ok(v);
    }
    if let Some(v) = env_nonempty("HOSTNAME") {
        return Ok(v);
    }
    if let Some(v) = read_trimmed("/etc/hostname") {
        return Ok(v);
    }

    Ok("local".to_string())
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_base_dir() -> PathBuf {
    if let Some(v) = env_nonempty("RITMA_BASE_DIR") {
        return PathBuf::from(v);
    }

    let candidates = base_dir_candidates();

    // Prefer existing storage roots so we don't "lose" the existing DB/output.
    for c in &candidates {
        if c.as_os_str().is_empty() {
            continue;
        }
        if c.join("index_db.sqlite").exists() || c.join("RITMA_OUT").is_dir() {
            return c.clone();
        }
    }

    // Otherwise, pick the first usable preferred location.
    for c in candidates {
        if c.as_os_str().is_empty() {
            continue;
        }
        if is_dir_writable_or_creatable(&c) {
            return c;
        }
    }

    PathBuf::from("./.ritma/data")
}

fn base_dir_candidates() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/var/lib/ritma"),
        PathBuf::from("/data"),
        PathBuf::from("/var/ritma/data"),
        home_dir_candidate(),
        PathBuf::from("./.ritma/data"),
    ]
}

fn home_dir_candidate() -> PathBuf {
    if let Some(home) = env_nonempty("HOME") {
        return PathBuf::from(home).join(".ritma").join("data");
    }
    PathBuf::new()
}

fn is_dir_writable_or_creatable(dir: &Path) -> bool {
    if dir.exists() {
        return is_writable_dir(dir);
    }

    let Some(parent) = dir.parent() else {
        return false;
    };
    if parent.as_os_str().is_empty() {
        return false;
    }
    if !parent.exists() {
        return false;
    }
    is_writable_dir(parent)
}

fn is_writable_dir(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }

    let probe = dir.join(format!(
        ".ritma_probe_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    match std::fs::write(&probe, b"probe") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn resolve_lock_dir(base_dir: &Path) -> PathBuf {
    if let Some(v) = env_nonempty("RITMA_SIDECAR_LOCK_DIR") {
        if v.len() <= 4096 && !v.contains('\0') {
            return PathBuf::from(v);
        }
    }

    // Prefer /run/ritma/locks, but only if we can create/use it.
    let preferred = PathBuf::from("/run/ritma/locks");
    if ensure_dir_usable(&preferred) {
        return preferred;
    }

    let tmp = PathBuf::from("/tmp/ritma/locks");
    if ensure_dir_usable(&tmp) {
        return tmp;
    }

    base_dir.join("locks")
}

fn ensure_dir_usable(dir: &Path) -> bool {
    if dir.exists() {
        return is_writable_dir(dir);
    }
    std::fs::create_dir_all(dir).is_ok() && is_writable_dir(dir)
}

fn sanitize_id(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }

    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        return "local".to_string();
    }
    if out.len() > 80 {
        return out[..80].to_string();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn resolve_cctv_requires_node_id_by_default() {
        let _g = env_guard();
        std::env::remove_var("RITMA_NODE_ID");
        std::env::remove_var("RITMA_HOST_ID");
        std::env::remove_var("RITMA_ALLOW_NODE_ID_FALLBACK");

        let r = StorageContract::resolve_cctv();
        assert!(r.is_err());
    }

    #[test]
    fn resolve_cctv_allows_node_id_fallback_when_enabled() {
        let _g = env_guard();
        std::env::remove_var("RITMA_NODE_ID");
        std::env::remove_var("RITMA_HOST_ID");
        std::env::set_var("RITMA_ALLOW_NODE_ID_FALLBACK", "1");

        let base = std::env::temp_dir().join(format!(
            "ritma_contract_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let idx = base.join("index_db.sqlite");
        let out = base.join("RITMA_OUT");
        let locks = base.join("locks");

        std::env::set_var("RITMA_BASE_DIR", &base);
        std::env::set_var("INDEX_DB_PATH", &idx);
        std::env::set_var("RITMA_OUT_DIR", &out);
        std::env::set_var("RITMA_SIDECAR_LOCK_DIR", &locks);

        let r = StorageContract::resolve_cctv();
        assert!(r.is_ok());

        std::env::remove_var("RITMA_BASE_DIR");
        std::env::remove_var("INDEX_DB_PATH");
        std::env::remove_var("RITMA_OUT_DIR");
        std::env::remove_var("RITMA_SIDECAR_LOCK_DIR");
        std::env::remove_var("RITMA_ALLOW_NODE_ID_FALLBACK");
    }

    #[test]
    fn resolve_cctv_rejects_relative_index_db_path() {
        let _g = env_guard();
        std::env::set_var("RITMA_ALLOW_NODE_ID_FALLBACK", "1");
        std::env::set_var("INDEX_DB_PATH", "./index_db.sqlite");

        let r = StorageContract::resolve_cctv();
        assert!(r.is_err());

        std::env::remove_var("INDEX_DB_PATH");
        std::env::remove_var("RITMA_ALLOW_NODE_ID_FALLBACK");
    }
}
