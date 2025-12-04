use std::collections::{BTreeMap, HashMap};

use core_types::{Hash, ParamBag, UID, Sig, LogicRef, BoundaryTag, ZkArcCommitment};
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
    ListRoots,
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

fn verify_signature(
    entity_id: UID,
    root_id: UID,
    signature: &Sig,
    data: &[u8],
    addr_heap_hash: &Hash,
    hook_hash: &Hash,
) -> Result<()> {
    let key_hex = match std::env::var("UTLD_SIG_KEY") {
        Ok(k) => k,
        Err(_) => return Ok(()),
    };

    let key_bytes = match hex::decode(&key_hex) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("UTLD_SIG_KEY is not valid hex; skipping signature verification");
            return Ok(());
        }
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
    use super::u128_as_string;
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
        NodeRequest::ListRoots => {
            let root_ids = node
                .roots_iter()
                .map(|r| r.root_id.0)
                .collect::<Vec<_>>();
            NodeResponse::Roots { root_ids }
        }
    }
}
