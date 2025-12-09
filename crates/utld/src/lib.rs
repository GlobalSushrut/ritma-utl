use std::collections::{BTreeMap, HashMap};

use core_types::{Hash, ParamBag, UID, Sig, LogicRef, BoundaryTag, ZkArcCommitment, hash_bytes};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sot_root::StateOfTruthRoot;
use clock::TimeTick;
use handshake::TransitionHandshake;
use tata::TataFrame;
use dig_mem::{DigRecord, DigFile};
use entropy_tree::EntropyBin;
use distillium::DistilliumMicroProof;
use tracer::UnknownLogicCapsule;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum UtlError {
    UnknownRoot(UID),
    NoRecordsForRoot(UID),
    InvalidSignature(UID),
}

fn persist_roots(roots: &HashMap<UID, StateOfTruthRoot>) -> std::io::Result<()> {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;

    #[derive(Serialize)]
    struct PersistedState<'a> {
        roots: Vec<&'a StateOfTruthRoot>,
    }

    let base = std::env::var("UTLD_STATE_FILE").unwrap_or_else(|_| "./utld_roots.json".to_string());
    let path = PathBuf::from(base);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let state = PersistedState {
        roots: roots.values().collect(),
    };

    let json = serde_json::to_string_pretty(&state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let tmp_path = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(tmp_path, path)?;

    Ok(())
}

pub type Result<T> = std::result::Result<T, UtlError>;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeRequest {
    RegisterRoot {
        #[serde(with = "u128_as_string")]
        root_id: u128,
        root_hash: [u8; 32],
        root_params: BTreeMap<String, String>,
        #[serde(with = "u128_as_string")]
        tx_hook: u128,
        zk_arc_commit: Vec<u8>,
    },
    RecordTransition {
        #[serde(with = "u128_as_string")]
        entity_id: u128,
        #[serde(with = "u128_as_string")]
        root_id: u128,
        signature: Vec<u8>,
        data: Vec<u8>,
        addr_heap_hash: [u8; 32],
        p_container: BTreeMap<String, String>,
        logic_ref: String,
        wall: String,
        hook_hash: [u8; 32],
    },
    BuildDigFile {
        #[serde(with = "u128_as_string")]
        root_id: u128,
        #[serde(with = "u128_as_string")]
        file_id: u128,
        time_start: u64,
        time_end: u64,
    },
    BuildEntropyBin {
        #[serde(with = "u128_as_string")]
        root_id: u128,
        #[serde(with = "u128_as_string")]
        bin_id: u128,
    },
    PolicyBurn {
        request: PolicyBurnRequest,
    },
    ListRoots,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PolicyBurnRequest {
    pub policy_id: String,
    pub version: u64,
    pub policy_hash_hex: String,
    #[serde(default)]
    pub cue_hash_hex: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub signature_hex: Option<String>,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NodeResponse {
    Ok,
    DigFileSummary {
        #[serde(with = "u128_as_string")]
        root_id: u128,
        #[serde(with = "u128_as_string")]
        file_id: u128,
        merkle_root: [u8; 32],
        record_count: usize,
    },
    EntropyBinSummary {
        #[serde(with = "u128_as_string")]
        root_id: u128,
        #[serde(with = "u128_as_string")]
        bin_id: u128,
        local_entropy: f64,
    },
    Roots {
        #[serde(with = "u128_vec_as_string")]
        root_ids: Vec<u128>,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Debug)]
pub struct RecordTransitionRequest {
    pub entity_id: UID,
    pub root_id: UID,
    pub signature: Sig,
    pub data: Vec<u8>,
    pub addr_heap_hash: Hash,
    pub p_container: ParamBag,
    pub logic_ref: LogicRef,
    pub wall: BoundaryTag,
    pub hook_hash: Hash,
}

pub struct UtlNode {
    roots: HashMap<UID, StateOfTruthRoot>,
    records: HashMap<UID, Vec<DigRecord>>,
    entropy_bins: HashMap<UID, Vec<EntropyBin>>,
    capsules: HashMap<UID, Vec<UnknownLogicCapsule>>,
    sealed_files: HashMap<UID, Vec<DigFile>>,
    micro_proofs: HashMap<UID, Vec<DistilliumMicroProof>>,
}

impl UtlNode {
    pub fn new() -> Self {
        Self {
            roots: HashMap::new(),
            records: HashMap::new(),
            entropy_bins: HashMap::new(),
            capsules: HashMap::new(),
            sealed_files: HashMap::new(),
            micro_proofs: HashMap::new(),
        }
    }

    pub fn register_root(&mut self, root: StateOfTruthRoot) {
        self.roots.insert(root.root_id, root);
        if let Err(e) = persist_roots(&self.roots) {
            eprintln!("failed to persist roots: {}", e);
        }
    }

    pub fn root(&self, id: UID) -> Option<&StateOfTruthRoot> {
        self.roots.get(&id)
    }

    pub fn record_transition(
        &mut self,
        entity_id: UID,
        root_id: UID,
        signature: Sig,
        data: Vec<u8>,
        addr_heap_hash: Hash,
        p_container: ParamBag,
        logic_ref: LogicRef,
        wall: BoundaryTag,
        hook_hash: Hash,
    ) -> Result<TransitionHandshake> {
        let req = RecordTransitionRequest {
            entity_id,
            root_id,
            signature,
            data,
            addr_heap_hash,
            p_container,
            logic_ref,
            wall,
            hook_hash,
        };
        self.record_transition_with(req)
    }

    pub fn record_transition_with(
        &mut self,
        req: RecordTransitionRequest,
    ) -> Result<TransitionHandshake> {
        let RecordTransitionRequest {
            entity_id,
            root_id,
            signature,
            data,
            addr_heap_hash,
            p_container,
            logic_ref,
            wall,
            hook_hash,
        } = req;

        let root = self
            .roots
            .get(&root_id)
            .cloned()
            .ok_or(UtlError::UnknownRoot(root_id))?;

        let tick = TimeTick::now();

        // Verify signature if UTLD_SIG_KEY is configured.
        verify_signature(
            entity_id,
            root_id,
            &signature,
            &data,
            &addr_heap_hash,
            &hook_hash,
        )?;

        let handshake = TransitionHandshake {
            entity_id,
            sot_root: root.clone(),
            clock_tick: tick,
            signature,
        };

        let frame = TataFrame::new(
            data,
            tick,
            root.root_hash.clone(),
            p_container,
            logic_ref,
            wall,
        );

        let record = DigRecord {
            addr_heap_hash,
            p_container: frame.params.clone(),
            timeclock: tick,
            data_container: TataFrame::new(
                frame.data,
                frame.timeclock,
                frame.hash_root,
                frame.params,
                frame.logic_ref,
                frame.wall,
            ),
            hook_hash,
        };

        self.records
            .entry(root_id)
            .or_insert_with(Vec::new)
            .push(record);

        Ok(handshake)
    }

    pub fn roots_iter(&self) -> impl Iterator<Item = &StateOfTruthRoot> {
        self.roots.values()
    }

    pub fn record_policy_burn_event(
        &mut self,
        root_id: UID,
        params: ParamBag,
        data: Vec<u8>,
    ) -> Result<()> {
        let root = self
            .roots
            .get(&root_id)
            .cloned()
            .ok_or(UtlError::UnknownRoot(root_id))?;

        let tick = TimeTick::now();

        let frame = TataFrame::new(
            data,
            tick,
            root.root_hash.clone(),
            params,
            LogicRef("policy_burn".to_string()),
            BoundaryTag("policy".to_string()),
        );

        let record = DigRecord {
            addr_heap_hash: Hash([0u8; 32]),
            p_container: frame.params.clone(),
            timeclock: tick,
            data_container: TataFrame::new(
                frame.data,
                frame.timeclock,
                frame.hash_root,
                frame.params,
                frame.logic_ref,
                frame.wall,
            ),
            hook_hash: Hash([0u8; 32]),
        };

        self.records
            .entry(root_id)
            .or_insert_with(Vec::new)
            .push(record);

        Ok(())
    }

    pub fn records_for_root_mut(&mut self, root_id: UID) -> Option<&mut Vec<DigRecord>> {
        self.records.get_mut(&root_id)
    }

    pub fn records_for_root(&self, root_id: UID) -> Option<&[DigRecord]> {
        self.records.get(&root_id).map(|v| v.as_slice())
    }

    pub fn entropy_bins_for_root(&self, root_id: UID) -> Option<&[EntropyBin]> {
        self.entropy_bins.get(&root_id).map(|v| v.as_slice())
    }

    pub fn capsules_for_root(&self, root_id: UID) -> Option<&[UnknownLogicCapsule]> {
        self.capsules.get(&root_id).map(|v| v.as_slice())
    }

    pub fn build_dig_file_for_root(
        &self,
        root_id: UID,
        file_id: UID,
        time_range: (u64, u64),
    ) -> Result<DigFile> {
        // Ensure the root exists so callers cannot accidentally create orphan files.
        self
            .roots
            .get(&root_id)
            .ok_or(UtlError::UnknownRoot(root_id))?;

        let records = self.records.get(&root_id).cloned().unwrap_or_default();
        Ok(DigFile::from_records(file_id, time_range, records))
    }

    pub fn seal_dig_for_root(
        &mut self,
        root_id: UID,
        file_id: UID,
        time_range: (u64, u64),
    ) -> Result<DigFile> {
        let dig = self.build_dig_file_for_root(root_id, file_id, time_range)?;

        self.sealed_files
            .entry(root_id)
            .or_insert_with(Vec::new)
            .push(dig.clone());

        // Clear in-memory records for this root after sealing.
        self.records.insert(root_id, Vec::new());

        Ok(dig)
    }

    pub fn build_entropy_bin_for_root(
        &mut self,
        root_id: UID,
        bin_id: UID,
    ) -> Result<EntropyBin> {
        self
            .roots
            .get(&root_id)
            .ok_or(UtlError::UnknownRoot(root_id))?;

        let records = self
            .records
            .get(&root_id)
            .ok_or(UtlError::NoRecordsForRoot(root_id))?;

        let bin = EntropyBin::from_records(bin_id, records);
        self
            .entropy_bins
            .entry(root_id)
            .or_insert_with(Vec::new)
            .push(bin.clone());
        Ok(bin)
    }

    pub fn record_unknown_logic_capsule(
        &mut self,
        root_id: UID,
        capsule: UnknownLogicCapsule,
    ) -> Result<()> {
        self
            .roots
            .get(&root_id)
            .ok_or(UtlError::UnknownRoot(root_id))?;

        self
            .capsules
            .entry(root_id)
            .or_insert_with(Vec::new)
            .push(capsule);

        Ok(())
    }

    pub fn generate_micro_proof_for_root(&mut self, root_id: UID) -> Result<DistilliumMicroProof> {
        let root = self
            .roots
            .get(&root_id)
            .cloned()
            .ok_or(UtlError::UnknownRoot(root_id))?;

        let state_hash = root.root_hash.clone();
        let proof = DistilliumMicroProof::new(root_id, state_hash, true, None);

        self.micro_proofs
            .entry(root_id)
            .or_insert_with(Vec::new)
            .push(proof.clone());

        Ok(proof)
    }
}

fn load_sig_key() -> Option<Vec<u8>> {
    use std::env;
    use std::fs;

    // Prefer file-based key if provided.
    if let Ok(path) = env::var("UTLD_SIG_KEY_FILE") {
        match fs::read_to_string(&path) {
            Ok(text) => match hex::decode(text.trim()) {
                Ok(b) => return Some(b),
                Err(e) => {
                    eprintln!("UTLD_SIG_KEY_FILE is not valid hex ({}); skipping signature verification", e);
                    return None;
                }
            },
            Err(e) => {
                eprintln!("failed to read UTLD_SIG_KEY_FILE ({}); skipping signature verification", e);
                return None;
            }
        }
    }

    // Fallback to environment variable.
    if let Ok(key_hex) = env::var("UTLD_SIG_KEY") {
        match hex::decode(&key_hex) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("UTLD_SIG_KEY is not valid hex ({}); skipping signature verification", e);
                None
            }
        }
    } else {
        None
    }
}

fn load_policy_burn_key() -> std::result::Result<Option<Vec<u8>>, String> {
    use std::env;
    use std::fs;

    // Prefer file-based key if provided.
    if let Ok(path) = env::var("UTLD_POLICY_BURN_KEY_FILE") {
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read UTLD_POLICY_BURN_KEY_FILE: {}", e))?;
        let bytes = hex::decode(text.trim())
            .map_err(|_| "UTLD_POLICY_BURN_KEY_FILE is not valid hex".to_string())?;
        return Ok(Some(bytes));
    }

    // Fallback to environment variable.
    if let Ok(key_hex) = env::var("UTLD_POLICY_BURN_KEY") {
        let bytes = hex::decode(&key_hex)
            .map_err(|_| "UTLD_POLICY_BURN_KEY is not valid hex".to_string())?;
        Ok(Some(bytes))
    } else {
        Ok(None)
    }
}

fn verify_signature(
    entity_id: UID,
    root_id: UID,
    signature: &Sig,
    data: &[u8],
    addr_heap_hash: &Hash,
    hook_hash: &Hash,
) -> Result<()> {
    let key_bytes = match load_sig_key() {
        Some(b) => b,
        None => return Ok(()),
    };

    type HmacSha256 = Hmac<Sha256>;

    let mut buf = Vec::new();
    buf.extend_from_slice(&entity_id.0.to_le_bytes());
    buf.extend_from_slice(&root_id.0.to_le_bytes());
    buf.extend_from_slice(&addr_heap_hash.0);
    buf.extend_from_slice(&hook_hash.0);
    buf.extend_from_slice(data);

    let mut mac = match HmacSha256::new_from_slice(&key_bytes) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("failed to create HMAC from UTLD_SIG_KEY; skipping signature verification");
            return Ok(());
        }
    };
    mac.update(&buf);
    let expected = mac.finalize().into_bytes();

    if signature.0 != expected.as_slice() {
        return Err(UtlError::InvalidSignature(root_id));
    }

    Ok(())
}

mod u128_as_string {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<u128>().map_err(serde::de::Error::custom)
    }
}

mod u128_vec_as_string {
    use serde::{self, Deserialize, Deserializer, Serializer, Serialize};

    pub fn serialize<S>(values: &Vec<u128>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let strings: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        strings.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::<String>::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| s.parse::<u128>().map_err(serde::de::Error::custom))
            .collect()
    }
}

fn format_error(e: UtlError) -> String {
    match e {
        UtlError::UnknownRoot(id) => format!("unknown_root: {}", id.0),
        UtlError::NoRecordsForRoot(id) => format!("no_records_for_root: {}", id.0),
        UtlError::InvalidSignature(id) => format!("invalid_signature_for_root: {}", id.0),
    }
}

pub fn handle_request(node: &mut UtlNode, req: NodeRequest) -> NodeResponse {
    match req {
        NodeRequest::RegisterRoot {
            root_id,
            root_hash,
            root_params,
            tx_hook,
            zk_arc_commit,
        } => {
            let root = StateOfTruthRoot::new(
                UID(root_id),
                Hash(root_hash),
                ParamBag(root_params),
                UID(tx_hook),
                ZkArcCommitment(zk_arc_commit),
            );
            node.register_root(root);
            NodeResponse::Ok
        }
        NodeRequest::RecordTransition {
            entity_id,
            root_id,
            signature,
            data,
            addr_heap_hash,
            p_container,
            logic_ref,
            wall,
            hook_hash,
        } => match node.record_transition(
            UID(entity_id),
            UID(root_id),
            Sig(signature),
            data,
            Hash(addr_heap_hash),
            ParamBag(p_container),
            LogicRef(logic_ref),
            BoundaryTag(wall),
            Hash(hook_hash),
        ) {
            Ok(_) => NodeResponse::Ok,
            Err(e) => NodeResponse::Error {
                message: format_error(e),
            },
        },
        NodeRequest::BuildDigFile {
            root_id,
            file_id,
            time_start,
            time_end,
        } => match node.build_dig_file_for_root(UID(root_id), UID(file_id), (time_start, time_end))
        {
            Ok(dig) => NodeResponse::DigFileSummary {
                root_id,
                file_id,
                merkle_root: dig.merkle_root.0,
                record_count: dig.dig_records.len(),
            },
            Err(e) => NodeResponse::Error {
                message: format_error(e),
            },
        },
        NodeRequest::BuildEntropyBin { root_id, bin_id } =>
            match node.build_entropy_bin_for_root(UID(root_id), UID(bin_id)) {
                Ok(bin) => NodeResponse::EntropyBinSummary {
                    root_id,
                    bin_id,
                    local_entropy: bin.local_entropy,
                },
                Err(e) => NodeResponse::Error {
                    message: format_error(e),
                },
            },
        NodeRequest::PolicyBurn { request } => {
            let req_clone = request.clone();
            match handle_policy_burn(request) {
                Ok(()) => {
                    // Optionally also record this burn as a DigRecord on a dedicated
                    // policy root, if UTLD_POLICY_ROOT_ID is configured and valid.
                    if let Ok(root_raw) = std::env::var("UTLD_POLICY_ROOT_ID") {
                        match root_raw.parse::<u128>() {
                            Ok(root_u128) => {
                                let root_id = UID(root_u128);

                                let mut map = BTreeMap::new();
                                map.insert("event_kind".to_string(), "policy_burn".to_string());
                                map.insert("policy_id".to_string(), req_clone.policy_id.clone());
                                map.insert("version".to_string(), req_clone.version.to_string());
                                map.insert("policy_hash_hex".to_string(), req_clone.policy_hash_hex.clone());
                                if let Some(cue) = req_clone.cue_hash_hex.clone() {
                                    map.insert("cue_hash_hex".to_string(), cue);
                                }
                                if let Some(issuer) = req_clone.issuer.clone() {
                                    map.insert("issuer".to_string(), issuer);
                                }

                                let data = match serde_json::to_vec(&req_clone) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        eprintln!(
                                            "failed to serialize PolicyBurnRequest for dig record: {}",
                                            e
                                        );
                                        Vec::new()
                                    }
                                };

                                let params = ParamBag(map);
                                if let Err(e) = node.record_policy_burn_event(root_id, params, data) {
                                    eprintln!("failed to record policy burn as dig record: {:?}", e);
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "UTLD_POLICY_ROOT_ID is not a valid u128 ({}); skipping policy burn dig record",
                                    e
                                );
                            }
                        }
                    }

                    NodeResponse::Ok
                }
                Err(msg) => NodeResponse::Error { message: msg },
            }
        },
        NodeRequest::ListRoots => {
            let root_ids = node
                .roots_iter()
                .map(|r| r.root_id.0)
                .collect::<Vec<_>>();
            NodeResponse::Roots { root_ids }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PolicyBurnEntry {
    ts: u64,
    policy_id: String,
    version: u64,
    policy_hash_hex: String,
    #[serde(default)]
    cue_hash_hex: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    signature_hex: Option<String>,
    #[serde(default)]
    meta: BTreeMap<String, String>,
    #[serde(default)]
    prev_entry_hash: Option<String>,
}

fn policy_ledger_path() -> String {
    std::env::var("UTLD_POLICY_LEDGER").unwrap_or_else(|_| "./policy_ledger.jsonl".to_string())
}

fn compute_policy_entry_hash(prev: Option<&str>, line: &[u8]) -> String {
    let mut data = Vec::new();
    if let Some(p) = prev {
        data.extend_from_slice(p.as_bytes());
    }
    data.extend_from_slice(line);

    let hash = hash_bytes(&data);
    let mut s = String::with_capacity(64);
    for b in &hash.0 {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn load_last_policy_version(policy_id: &str) -> std::io::Result<Option<u64>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader, ErrorKind};

    let path = policy_ledger_path();
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(e);
        }
    };

    let reader = BufReader::new(file);
    let mut last: Option<u64> = None;
    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };
        if line.trim().is_empty() {
            continue;
        }
        let entry: PolicyBurnEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.policy_id == policy_id {
            last = Some(last.map(|v| v.max(entry.version)).unwrap_or(entry.version));
        }
    }

    Ok(last)
}

fn append_policy_burn_entry(entry: &PolicyBurnEntry) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use fs2::FileExt;

    let path = policy_ledger_path();

    let head_path = format!("{}.head", path);
    let prev_hash = std::fs::read_to_string(&head_path)
        .ok()
        .map(|s| s.trim().to_string());

    let mut chained_entry = entry.clone();
    chained_entry.prev_entry_hash = prev_hash.clone();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    // Serialize appends with an advisory file lock so multiple utld instances
    // cannot interleave writes.
    file.lock_exclusive()?;

    let line = serde_json::to_string(&chained_entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;

    let current_hash = compute_policy_entry_hash(prev_hash.as_deref(), line.as_bytes());
    if let Err(e) = std::fs::write(&head_path, format!("{}\n", current_hash)) {
        eprintln!("failed to update policy ledger head {}: {}", head_path, e);
    }

    Ok(())
}

fn handle_policy_burn(req: PolicyBurnRequest) -> std::result::Result<(), String> {
    if req.policy_id.trim().is_empty() {
        return Err("policy_id must be non-empty".to_string());
    }
    if req.version == 0 {
        return Err("policy version must be > 0".to_string());
    }

    let last = load_last_policy_version(&req.policy_id)
        .map_err(|e| format!("failed to read policy ledger: {}", e))?;
    if let Some(last_v) = last {
        if req.version <= last_v {
            return Err(format!(
                "policy version {} must be greater than last version {} for policy_id {}",
                req.version, last_v, req.policy_id
            ));
        }
    }

    if let Some(key_bytes) = load_policy_burn_key()? {
        let sig_hex = req
            .signature_hex
            .clone()
            .ok_or_else(|| "policy burn signature required when UTLD_POLICY_BURN_KEY is set".to_string())?;
        let sig_bytes = hex::decode(&sig_hex)
            .map_err(|e| format!("invalid signature_hex: {}", e))?;

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&key_bytes)
            .map_err(|_| "failed to create HMAC from UTLD_POLICY_BURN_KEY".to_string())?;

        let cue = req.cue_hash_hex.clone().unwrap_or_default();
        let canonical = format!(
            "{}:{}:{}:{}",
            req.policy_id, req.version, req.policy_hash_hex, cue
        );
        mac.update(canonical.as_bytes());
        let expected = mac.finalize().into_bytes();

        if expected.as_slice() != sig_bytes.as_slice() {
            return Err("invalid policy burn signature".to_string());
        }
    }

    let tick = TimeTick::now();

    let entry = PolicyBurnEntry {
        ts: tick.raw_time,
        policy_id: req.policy_id,
        version: req.version,
        policy_hash_hex: req.policy_hash_hex,
        cue_hash_hex: req.cue_hash_hex,
        issuer: req.issuer,
        signature_hex: req.signature_hex,
        meta: req.meta,
        prev_entry_hash: None,
    };

    append_policy_burn_entry(&entry)
        .map_err(|e| format!("failed to append policy ledger entry: {}", e))
}
