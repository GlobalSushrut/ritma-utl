# Ritma CCTV Hardening — Remaining Checklist (Execution Order)

This file lists **what’s left** (not done yet) from `RITMA_INFRASTRUCTURE_CCTV_ROADMAP.md`, in the **recommended order to execute**.

Reference architecture: `docs/STORAGE_ARCHITECTURE_CTGF_PROOFPACK.md`.

## Recently completed (ProofPack export / demo UX)

### CLI ProofPack export (CBOR-first)

- [x] ProofPack export defaults to canonical CBOR artifacts (JSON only via compatibility flags)
- [x] `export-proof --at <ts>` suggests nearest ML windows and a recommended `--ml-id`
- [x] `--serve` auto-selects a free port when the requested port is already in use
- [x] Embedded `--serve` provides CBOR→JSON API endpoints (e.g. `/api/manifest.json`) for the viewer

## Planned next (execute in order)

1. Standardize the **deployment contract** across systemd/Docker/Kubernetes (Section 0.1)
2. Add **host systemd unit + least-privilege hardening** for `tracer_sidecar` (Section 0.2)
3. Finalize **host persistent storage baseline** (`/var/lib/ritma`, `INDEX_DB_PATH`, `RITMA_OUT/`) (Section 0.3)
4. Enforce **cross-mode single-writer** using `/run/ritma/locks` everywhere (Section 0.4)

## 0) Phase 1 completion gate (do these next)

### 0.1 Standardize the deployment contract (all modes)
- [x] Make `RITMA_NODE_ID` mandatory in CCTV mode (stable per host)
- [x] Standardize `INDEX_DB_PATH` (stable + persistent)
- [x] Standardize lock directory: `RITMA_SIDECAR_LOCK_DIR=/run/ritma/locks`
- [x] Standardize eBPF object path: `RITMA_EBPF_OBJECT_PATH` (or equivalent)
- [x] Ensure **systemd + Docker + Kubernetes** all use the same values/paths

### 0.2 Host default deployment (systemd)
- [x] Add systemd unit for `tracer_sidecar`
- [ ] Ensure least privilege:
  - [x] minimal Linux capabilities
  - [x] strict `seccomp` / `NoNewPrivileges`
  - [x] filesystem protections (`ProtectSystem`, `ProtectHome`, etc.)

### 0.3 Host persistent storage baseline (local-first Output Container v2: `RITMA_OUT/`)
- [x] Standardize a base data dir (default: `/var/lib/ritma`) for non-custodial storage
- [x] Hot store (thin, today): `/var/lib/ritma/index_db.sqlite` (canonical events + minimal edges)
- [x] Output container root: `/var/lib/ritma/RITMA_OUT/`
  - [x] `_meta/` (store id + keys + schema + health)
  - [ ] `catalog/YYYY/MM/DD/day.cbor.zst`
  - [ ] `windows/YYYY/MM/DD/HH/` (hour header + proofs + micro windows + blocks + indexes)
  - [ ] `graph/` (hourly edges + global dict)
  - [ ] `ctgf/cones/v0001/` (versioned cone library)
  - [ ] `cas/b3/ab/cd/<hash>` (payload chunks only when thick/full)
  - [ ] `accounting/YYYY/MM/DD/account.cbor.zst`
  - [ ] `cases/CASE_*/` (frozen windows + signed manifest + access log)
  - [ ] `exports/CASE_*/` (portable evidence bundles)
- [x] Set correct ownership + permissions for all above paths
- [x] Define rotation + retention policy for IndexDB + RITMA_OUT (must respect case freezes)
  - [x] `ritma retention run` CLI command (dry-run by default, `--apply` to execute)
  - [x] Rotate IndexDB by size threshold (`--max-size-mb`)
  - [x] Keep N rotated files (`--keep`)
  - [x] systemd timer template (`ritma-retention.timer` + `.service`)

### 0.4 Cross-mode single-writer enforcement
- [x] Enforce “one writer per host” across:
  - [x] host systemd (flock in tracer_sidecar)
  - [x] docker sidecar (flock in tracer_sidecar)
  - [x] kubernetes daemonset (flock in tracer_sidecar)
- [x] Ensure all modes share `/run/ritma/locks` consistently (hostPath / volume mount)

### 0.5 Storage format + evidence discipline (forensic/audit grade, still lightweight)
- [x] Canonical event representation is deterministic + versioned (stable hashes across machines)
  - [x] `CanonicalEventAtom` struct in `ritma_contract::canonical`
  - [x] `EVENT_SCHEMA_VERSION` included in hash input
  - [x] `canonical_hash()` method for deterministic hashing
- [x] CBOR tuple/array encoding only (atoms/CTGF/proofs), no map encoding in hashed artifacts
  - [x] `to_cbor_tuple()` methods on all canonical types
- [x] Hot store contains “meaning” only (thin events/edges + references, no heavy payloads)
- [x] Cold store uses CAS (deduped chunks + Merkle manifests) for “bytes” only when needed
  - [x] `ColdStore` with `store_payload()`, `retrieve_payload()`, `cleanup_expired()`
  - [x] `PayloadType` enum: PacketCapture, MemoryDump, BinarySample, FileContent, CoreDump, etc.
  - [x] `PayloadRef` with manifest root, metadata, retention policy
- [x] Proof ledger stores “trust”:
  - [x] periodic Merkle roots over canonical event hashes (`merkle_root_sha256`)
  - [x] `prev_root` chaining + signatures (`chain.cbor`, `chain.sig`)
  - [x] run identity metadata (`RunMeta`: host_id/node_id + boot_id + sensor_version + config digest)
- [x] Offline verification works from an exported bundle (no network required)
  - [x] `OfflineVerifier` with `verify_all()`, `verify_chain()`, `verify_hours()`
  - [x] `BundleExporter` with `export_range()` for standalone bundles
  - [x] `VerificationResult` with errors, warnings, and stats
- [ ] Optional (explicit opt-in): replicate proof roots to WORM storage / remote witness (custody stays local by default)
- [x] Capture modes exist to bound cost:
  - [x] thin always-on (`CaptureMode::Thin`)
  - [x] thick on trigger (`CaptureMode::Thick`)
  - [x] full only on case (`CaptureMode::Full`)
- [x] Human-time navigation exists:
  - [x] daily catalog (`catalog/YYYY/MM/DD/day.cbor.zst`)
  - [x] time-jump indexes (`index/timejump.cbor`)
- [x] Case freezing exists and blocks retention deletion (case manifests + access logs)
  - [x] `freeze_case()` creates `cases/CASE_ID/manifest.cbor` + `access_log.cbor.zst`
  - [x] `is_window_frozen()` checks if window overlaps any frozen case
  - [x] `list_frozen_cases()` enumerates all frozen cases
- [x] Accounting ledger exists (bytes, compression, dedupe, top talkers)
  - [x] `record_accounting()` writes daily `accounting/YYYY/MM/DD/account.cbor.zst`
  - [x] `get_accounting_summary()` returns `AccountingSummary` with compression/dedupe ratios
- [x] Cone library is versioned and referenced by windows (cone lib version + cone refs)
- [ ] Optional integrity anchors exist (daily anchors to WORM/TSA/UTLD/public ledger)

## 1) Deployment templates aligned to the contract

### 1.1 Docker “host CCTV” deployment template
- [x] Docker host CCTV template aligned:
  - [x] persistent DB mount
  - [x] lock dir mount
  - [x] strict security opts
  - [x] clear instructions to run/stop

### 1.2 Kubernetes DaemonSet template
- [x] K8s DaemonSet aligned:
  - [x] derive `RITMA_NODE_ID` from node identity (e.g. nodeName)
  - [x] hostPath mounts for DB + locks
  - [x] strict `securityContext` and defaults

### 1.3 Evidence discipline documentation
- [x] Document “append-only semantics” (no update/delete) and how enforcement works

## 2) Output Container v2 specs (RITMA_OUT + CTGF + ProofPack)

### 2.1 `_meta/` contract (keys + schema + health)
- [x] `store.cbor`: store identity + format version
- [x] Key material metadata:
  - [x] `keys/pubkeys.cbor` (`ensure_keys_meta()`)
  - [x] `keys/key_rotation_log.cbor.zst` (`ensure_keys_meta()`)
- [x] Schema artifacts:
  - [x] `schema/event_schema_v1.cbor` (`ensure_schema_meta()`)
  - [x] `schema/cone_schema_v1.cbor` (`ensure_schema_meta()`)
  - [x] `schema/proof_schema_v1.cbor` (`ensure_schema_meta()`)
- [x] Health artifacts:
  - [x] `health/last_compaction.cbor` (`ensure_health_meta()`)
  - [x] `health/stats_rolling_7d.cbor.zst` (`ensure_health_meta()`)

### 2.2 Canonical event atoms + dictionary (CBOR tuples)
- [x] Define atom tuple layout (positional): `tΔ`, `etype`, `actor`, `object`, `flags_class`, `arg_hash?`, `payload_ref?`
  - [x] `CanonicalEventAtom` struct in `ritma_contract::canonical`
- [x] Define deterministic hashing rules for atoms/instantiations (include schema version in hash input)
  - [x] `canonical_hash()` includes `EVENT_SCHEMA_VERSION` in hash
- [x] Define dictionary store (LMDB): strings → ids, file ids, flow ids, proc ids, namespace ids
  - [x] `DictionaryStore` trait with `get_or_insert`, `lookup`, `get_or_insert_batch`, `stats`
  - [x] `InMemoryDictionary` implementation with persistence via `LmdbDictionary`
  - [x] `DictEntryType` enum: String, FilePath, ProcessId, FlowId, NamespaceId, ContainerId, ServiceName
- [x] Define run metadata record (host_id/node_id, boot_id, sensor_version, config digest)
  - [x] `RunMeta` struct in `ritma_contract::canonical`

### 2.3 CTGF (cone library versioning + instantiation blocks)
- [x] Cone library versioning:
  - [x] `ctgf/cones/v0001/` with `cones.cbor.zst` + `cone_index.cbor` (`ConeLibrary`)
  - [x] window headers include `cone_lib_version` (via `CONE_LIB_VERSION` constant)
  - [x] per-hour `index/cone_refs.cbor` lists cone IDs used (`InstantiationBlockWriter::write_cone_refs`)
- [ ] Hot/cold cones split (performance + sustainability)
- [x] Define cone pattern representation (placeholders + versioning; append-only library)
  - [x] `ConePattern` struct with `cone_id`, `name`, `version`, `placeholders`, `pattern_hash`
- [x] Define instantiation record format: `cone_id`, `t_start`, placeholder→id mapping, counters/exceptions
  - [x] `ConeInstantiation` struct with `placeholder_values`, `event_count`, `exceptions`
- [x] Define storage cadence: hourly partition with numbered blocks (`windows/YYYY/MM/DD/HH/blocks/inst_0000.cbor.zst`)
  - [x] `InstantiationBlockWriter` with auto-flush at 1000 instantiations per block

### 2.4 Graph-lite index spec (LMDB/RocksDB)
- [x] Define edge types: exec lineage, proc→file, proc→flow
  - [x] `EdgeType` enum: ExecLineage, ProcToFile, ProcToFlow, FileToFile, ProcToProc, ContainerToProc
  - [x] `EdgeFlags` for READ/WRITE/EXEC/DELETE/CREATE/RENAME/SEND/RECV
- [x] Define hourly segment storage: `graph/edges/YYYY/MM/DD/HH/*.edges.cbor.zst`
  - [x] `HourlyEdgeWriter` with auto-flush at 10k edges
- [x] Define window pointer: `windows/.../index/edge_refs.cbor`
  - [x] `write_edge_refs()` method
- [x] Define key format: `(edge_type, src_id, time_bucket, dst_id)` → packed adjacency list
  - [x] `Edge::to_key()` produces 21-byte compact key
  - [x] `AdjacencyList` for grouped storage
  - [x] `GraphReader` for time-range queries

### 2.5 CAS (BLAKE3 chunk store) v0 spec (local-first; optional S3/MinIO)
- [x] Chunking: 1–4MB chunks
  - [x] `MIN_CHUNK_SIZE`, `MAX_CHUNK_SIZE`, `DEFAULT_CHUNK_SIZE` constants
- [x] Keying: `BLAKE3(chunk)`
  - [x] `blake3_hash()` function
- [x] Layout: `cas/b3/ab/cd/<hash>`
  - [x] `CasStore::chunk_path()` implements layout
- [x] Manifest format: Merkle manifest referencing chunk hashes (CBOR, versioned)
  - [x] `ChunkManifest` with `ChunkRef` list and Merkle root
  - [x] `store_data()` / `retrieve_data()` for full roundtrip
  - [x] `store_manifest()` / `load_manifest()` for persistence
- [ ] Optional S3/MinIO replication with lifecycle policies (Object Lock / WORM optional)

### 2.6 Micro-windows + ProofPacks (heap tree roots + signatures)
- [x] Partition concept:
  - [x] storage partition: hour (`windows/YYYY/MM/DD/HH/`)
  - [x] logical windows: micro windows inside hour (`micro/w000.*`)
- [x] Micro window files:
  - [x] `micro/w000.cbor` and `micro/w000.sig` (`MicroWindow`, `MicroSignature`)
- [x] Hour proof files:
  - [x] `proofs/hour_root.cbor`, `proofs/hour_root.sig`, `proofs/chain.cbor` (`HourRoot`, `HourSignature`, `ChainRecord`)
- [x] Define hash tree:
  - [x] leaf = `hash(canonical instantiation record)`
  - [x] micro root = Merkle over leaves (`merkle_root_sha256`)
  - [x] hour root = Merkle over micro roots (`HourRoot::new`)
- [x] Signature v0: software key (from `node_keystore`) + algorithm ids; v1: TPM/HSM
  - [x] `ProofPackWriter` with `add_micro_window()` and `finalize()`

### 2.7 Time-jump index (3 resolutions)
- [x] Build `index/t_1s.cbor`, `index/t_10s.cbor`, `index/t_60s.cbor`
  - [x] `TimeJumpWriter` with auto-bucketing at 1s, 10s, 60s resolutions
  - [x] `TimeJumpIndex` with BTreeMap for efficient range queries
- [x] Each entry points to `(block_id, offset)` and optional micro-window id/root id
  - [x] `TimeJumpEntry` struct with `micro_window_id`, `block_id`, `offset`, `micro_root`
  - [x] `TimeJumpReader` for loading and querying indexes

### 2.8 Daily catalog (instant "find the suspicious hour")
- [x] Build `catalog/YYYY/MM/DD/day.cbor.zst`
  - [x] `DailyCatalogWriter` with `finalize()` for compressed output
  - [x] `DailyCatalogReader` with `load()` and `list_dates()`
- [x] Store per-window summary: `t1,t2,host,boot,event_count,root,rule_triggers`
  - [x] `WindowSummary` struct with all fields
- [x] Store sketches: top processes, top outbound IPs, anomaly score, counts per event type
  - [x] `DailySketches` with `top_processes`, `top_outbound_ips`, `top_files`, `top_users`
  - [x] `EventTypeCounts` for proc_exec, file_open, net_connect, etc.
  - [x] `anomaly_score` and `alert_count` fields

### 2.9 Case freezing (retention locks + access logs)
- [x] Implement `cases/CASE_*/`:
  - [x] `manifest.cbor` via `freeze_case()` in `StorageContract`
  - [x] `access_log.cbor.zst` initialized on freeze
  - [x] `case_header.cbor` (extended metadata) via `CaseHeader` struct
  - [x] `frozen_windows.cbor` (explicit window list) via `FrozenWindowsList`
- [x] `CaseManager` with `create_case()`, `freeze_window()`, `is_timestamp_frozen()`
- [x] `CaseStatus` enum: Open, Frozen, Closed, Archived
- [ ] Catalog tagging includes `retention_lock=true` and `case_ids=[...]`
- [x] Retention/GC never deletes frozen windows
  - [x] `is_window_frozen()` checks overlap with frozen cases
  - [x] `list_frozen_cases()` enumerates all cases

### 2.10 Data accounting ledger (storage cost + provenance accounting)
- [x] Build `accounting/YYYY/MM/DD/account.cbor.zst`
  - [x] `record_accounting()` writes framed CBOR records
  - [x] `get_accounting_summary()` returns `AccountingSummary`
- [x] Track bytes by category (events, raw, compressed, deduped)
- [x] Track compression ratio + dedupe ratio
  - [x] `AccountingSummary::compression_ratio()` and `dedupe_ratio()`
- [x] Track top talkers (per-process/service breakdown)
  - [x] `AccountingAccumulator` with `record_process_event()`, `record_service_event()`
  - [x] `ExtendedAccounting` with `top_processes`, `top_services`, `top_containers`, `top_users`
  - [x] `CategoryBreakdown` for inst_blocks, indexes, cas_chunks, proofs, catalog, graph

### 2.11 Integrity anchor points (optional)
- [x] Define daily anchor artifacts (WORM + TSA/ledger/UTLD anchors)
  - [x] `DailyAnchor` with `day_root` computed from hour roots
  - [x] `AnchorType` enum: Worm, Tsa, PublicLedger, Utld, RemoteWitness
  - [x] `AnchorSubmission` with status lifecycle (Pending → Submitted → Confirmed)
- [x] Anchoring is opt-in and never blocks local operation
  - [x] `AnchorConfig` with `enabled = false` by default
  - [x] `AnchorManager` with `create_daily_anchor()`, `submit_anchor()`, `verify_anchor()`

### 2.12 Rotation + retention v0 spec (IndexDB + RITMA_OUT)
- [x] Rotate by size
- [x] Rotate by time
- [x] Keep N rotated units
- [x] Seal/close windows (ProofPacks) before deletion
- [x] Expire policy for raw/high-volume CAS payloads
- [x] Respect case freezes (retention locks)

### 2.13 Capture modes + triggers policy
- [x] Define modes: thin always-on, thick on trigger (60–300s), full on case
  - [x] `CaptureMode` enum: Thin, Thick, Full with `from_env()` and `retention_days()`
- [x] Define trigger set (exec from tmp/memfd, injection signals, priv-esc, egress spikes, secrets-path access, unknown binary hash)
  - [x] `TriggerType` enum with 12 trigger types and severity levels
  - [x] `TriggerPolicy` with configurable secrets_paths, tmp_paths, egress_threshold
- [x] Ensure triggers are auditable (trigger decision itself is logged as an event)
  - [x] `TriggerEvent` struct with full context (pid, comm, exe, details)
  - [x] `TriggerAuditLog` for append-only audit trail in `audit/triggers.cbor.zst`

### 2.14 Optional ClickHouse (multi-host hot query backend)
- [ ] Define ingestion from local thin atoms/edges into ClickHouse tables
- [ ] Partition by day (and tenant/cluster if applicable)
- [ ] Order by `(host_id, ns_id, time, pid, event_type)`
- [ ] Compression (ZSTD) + dictionary encoding for strings

## 3) “CCTV 6-core truth” remaining work

### Core 1: Kernel Event Truth
- [x] Expand tracepoints/LSM coverage beyond exec/open/connect/dns
  - [x] `KernelEventSource` enum: Tracepoint, LsmHook, Kprobe, Uprobe, PerfEvent, Audit
  - [x] `KernelEventCoverage` struct with event_type, source, tracepoint, lsm_hook
  - [x] `standard_kernel_coverage()` returns 14+ event types (proc_exec, file_open, socket_connect, ptrace, etc.)

### Core 2: Process / Actor Attribution
- [x] Exec-anchored immutable actor records (pid reuse protection via start_time)
  - [x] `ActorRecord` with `actor_id`, `pid`, `start_time_ns`, `ppid`, `uid/gid`, `exe_hash`
  - [x] `compute_actor_id()` deterministic from pid + start_time + exe_hash
- [x] Container/service attribution for all events (cgroup→container/service mapping)
  - [x] `NamespaceIds` struct with mnt_ns, pid_ns, net_ns, user_ns, etc.
  - [x] `with_container()` and `with_service()` methods

### Core 3: Temporal Integrity
- [x] Dual clocks per event (monotonic ordering + wall time)
  - [x] `DualTimestamp` with `monotonic_ns`, `wall_time_ns`, `boot_id`
  - [x] `cmp()` method for cross-boot ordering
- [x] Window sealing (count + hashes + signature) + immutable past windows
  - [x] `WindowSeal` with `merkle_root`, `prev_seal_hash`, `seal_hash`
  - [x] `compute_seal_hash()` for chained sealing

### Core 4: Data Volume Control & Compression
- [x] Rotation + summarization (window aggregates, dedup counters, TTL for raw)
  - [x] Covered by `ExtendedAccounting` and `CategoryBreakdown`
  - [x] `PayloadType::retention_days()` for TTL policies

### Core 5: Runtime Graph & Provenance
- [x] Runtime DAG (events/snapshots) + Merkle linking + diff-first state model
  - [x] `DagNode` with `node_id`, `node_type`, `snapshot_hash`
  - [x] `GraphNodeType` enum: Process, File, Socket, Container, Service, Host
  - [x] `StateDiff` with `prev_snapshot`, `new_snapshot`, `changes`
- [x] Queryable replay APIs ("state at t", "diff t0→t1")
  - [x] `StateSnapshot` with `EntityState` map and `finalize()` for snapshot ID
  - [x] `SnapshotDiff::compute()` detects added, removed, modified entities
  - [x] `SnapshotStore` with `find_snapshot_at()`, `diff()`, `query_entity_at()`, `entity_history()`

### Core 6: Tamper Resistance & Evidence Integrity
- [x] Append-only discipline + hash chaining + periodic ProofPack sealing
  - [x] `AppendOnlyEntry` with `sequence`, `entry_hash`, `prev_hash`, `payload_hash`
  - [x] `genesis()` and `next()` for chain construction
  - [x] `verify_chain()` for integrity verification
  - [x] `IntegritySummary` for verification results

## 4) Remaining Phase-1/Month-1 hardening items

- [ ] Add AppArmor/SELinux profiles
- [ ] Implement mTLS for all services
- [x] Evidence sealing pipeline: CTGF inst blocks → heap tree roots → signed window ProofPacks → optional remote witness anchor
  - [x] `SealingPipeline` with `process_hour()` and `process_day()`
  - [x] `PipelineStage` enum: Collecting, BuildingMicroRoots, BuildingHourRoot, Signing, Anchoring, Complete
  - [x] `HourPipelineStatus` tracking full pipeline state
  - [x] `MicroWindowData` for accumulating events into leaf hashes
- [ ] Complete eBPF program suite
  - [ ] PID/cgroup attribution for exec/open/connect
  - [ ] Probe tamper detection + auto-heal
- [ ] Implement state versioning engine
- [ ] Add hardware attestation (TPM)

## 5) Later phases (park until Phase 1 is solid)

### Quarter 1
- [ ] Full packet capture with XDP
- [ ] Container runtime hooks
- [ ] Kubernetes admission controllers
- [ ] Time-travel query system
- [ ] ML anomaly detection
- [ ] Distributed consensus

### Year 1
- [ ] Multi-cloud integration
- [ ] Blockchain anchoring
- [ ] Homomorphic encryption
- [ ] Predictive threat detection
- [ ] Global distribution
- [ ] Compliance automation
