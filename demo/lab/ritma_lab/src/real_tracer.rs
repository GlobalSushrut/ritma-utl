use anyhow::Result;
use std::path::PathBuf;
use tracing::info;

use common_models::{
    TraceEvent, TraceEventKind, TraceSourceKind,
    TraceActor, TraceTarget, TraceAttrs, hash_string_sha256,
};
use index_db::IndexDb;
use ritma_contract::StorageContract;

/// Real tracer integration - uses the SAME pipeline as tracer_sidecar
/// Events go to index_db.sqlite AND RITMA_OUT
pub struct RealTracer {
    index_db: IndexDb,
    contract: StorageContract,
    namespace_id: String,
    node_id: String,
    prev_hash: Option<String>,
    event_count: u64,
}

impl RealTracer {
    pub fn new(base_dir: PathBuf, node_id: String, namespace_id: String) -> Result<Self> {
        // Set environment for ritma_contract
        std::env::set_var("RITMA_NODE_ID", &node_id);
        std::env::set_var("RITMA_BASE_DIR", base_dir.to_string_lossy().to_string());
        std::env::set_var("RITMA_OUT_ENABLE", "1");

        let contract = StorageContract::resolve(ritma_contract::ResolveOpts {
            require_node_id: true,
            require_absolute_paths: false,
        }).map_err(|e| anyhow::anyhow!("Failed to resolve storage contract: {}", e))?;

        contract.ensure_out_layout()?;

        // Open index_db - same as tracer_sidecar
        let db_path = contract.index_db_path.to_string_lossy().to_string();
        let index_db = IndexDb::open(&db_path)?;

        info!(
            node_id = %node_id,
            namespace_id = %namespace_id,
            db_path = %db_path,
            out_dir = %contract.out_dir.display(),
            "Initialized real tracer (same pipeline as tracer_sidecar)"
        );

        Ok(Self {
            index_db,
            contract,
            namespace_id,
            node_id,
            prev_hash: None,
            event_count: 0,
        })
    }

    /// Record a process execution event - same as tracer_sidecar captures
    pub fn record_proc_exec(
        &mut self,
        pid: i64,
        ppid: i64,
        uid: i64,
        gid: i64,
        exe: &str,
        argv: &str,
        cwd: &str,
    ) -> Result<String> {
        let trace_id = format!("te_{}", uuid::Uuid::now_v7());
        let ts = chrono::Utc::now().to_rfc3339();

        let event = TraceEvent {
            trace_id: trace_id.clone(),
            ts: ts.clone(),
            namespace_id: self.namespace_id.clone(),
            source: TraceSourceKind::Runtime, // Lab simulates runtime events
            kind: TraceEventKind::ProcExec,
            actor: TraceActor {
                pid,
                ppid,
                uid,
                gid,
                net_ns: None,
                auid: None,
                ses: None,
                tty: None,
                euid: None,
                suid: None,
                fsuid: None,
                egid: None,
                comm_hash: Some(hash_string_sha256(exe)),
                exe_hash: Some(hash_string_sha256(exe)),
                comm: Some(exe.to_string()),
                exe: Some(exe.to_string()),
                container_id: None,
                service: None,
                build_hash: None,
            },
            target: TraceTarget {
                path_hash: None,
                dst: None,
                domain_hash: None,
                protocol: None,
                src: None,
                state: None,
                dns: None,
                path: None,
                inode: None,
                file_op: None,
            },
            attrs: TraceAttrs {
                argv_hash: Some(hash_string_sha256(argv)),
                cwd_hash: Some(hash_string_sha256(cwd)),
                bytes_out: None,
                argv: Some(argv.to_string()),
                cwd: Some(cwd.to_string()),
                bytes_in: None,
                env_hash: None,
            },
            lamport_ts: None,
            causal_parent: None,
            vclock: None,
        };

        self.insert_trace_event(&event)?;
        Ok(trace_id)
    }

    /// Record a file open event
    pub fn record_file_open(
        &mut self,
        pid: i64,
        ppid: i64,
        uid: i64,
        gid: i64,
        path: &str,
        file_op: Option<&str>,
    ) -> Result<String> {
        let trace_id = format!("te_{}", uuid::Uuid::now_v7());
        let ts = chrono::Utc::now().to_rfc3339();

        let event = TraceEvent {
            trace_id: trace_id.clone(),
            ts,
            namespace_id: self.namespace_id.clone(),
            source: TraceSourceKind::Runtime,
            kind: TraceEventKind::FileOpen,
            actor: TraceActor {
                pid,
                ppid,
                uid,
                gid,
                net_ns: None,
                auid: None,
                ses: None,
                tty: None,
                euid: None,
                suid: None,
                fsuid: None,
                egid: None,
                comm_hash: None,
                exe_hash: None,
                comm: None,
                exe: None,
                container_id: None,
                service: None,
                build_hash: None,
            },
            target: TraceTarget {
                path_hash: Some(hash_string_sha256(path)),
                dst: None,
                domain_hash: None,
                protocol: None,
                src: None,
                state: None,
                dns: None,
                path: Some(path.to_string()),
                inode: None,
                file_op: file_op.map(|s| s.to_string()),
            },
            attrs: TraceAttrs {
                argv_hash: None,
                cwd_hash: None,
                bytes_out: None,
                argv: None,
                cwd: None,
                bytes_in: None,
                env_hash: None,
            },
            lamport_ts: None,
            causal_parent: None,
            vclock: None,
        };

        self.insert_trace_event(&event)?;
        Ok(trace_id)
    }

    /// Record a network connection event
    pub fn record_net_connect(
        &mut self,
        pid: i64,
        ppid: i64,
        uid: i64,
        gid: i64,
        src: &str,
        dst: &str,
        protocol: &str,
        state: &str,
    ) -> Result<String> {
        let trace_id = format!("te_{}", uuid::Uuid::now_v7());
        let ts = chrono::Utc::now().to_rfc3339();

        let event = TraceEvent {
            trace_id: trace_id.clone(),
            ts,
            namespace_id: self.namespace_id.clone(),
            source: TraceSourceKind::Runtime,
            kind: TraceEventKind::NetConnect,
            actor: TraceActor {
                pid,
                ppid,
                uid,
                gid,
                net_ns: None,
                auid: None,
                ses: None,
                tty: None,
                euid: None,
                suid: None,
                fsuid: None,
                egid: None,
                comm_hash: None,
                exe_hash: None,
                comm: None,
                exe: None,
                container_id: None,
                service: None,
                build_hash: None,
            },
            target: TraceTarget {
                path_hash: None,
                dst: Some(dst.to_string()),
                domain_hash: Some(hash_string_sha256(dst)),
                protocol: Some(protocol.to_string()),
                src: Some(src.to_string()),
                state: Some(state.to_string()),
                dns: None,
                path: None,
                inode: None,
                file_op: None,
            },
            attrs: TraceAttrs {
                argv_hash: None,
                cwd_hash: None,
                bytes_out: Some(0),
                argv: None,
                cwd: None,
                bytes_in: Some(0),
                env_hash: None,
            },
            lamport_ts: None,
            causal_parent: None,
            vclock: None,
        };

        self.insert_trace_event(&event)?;
        Ok(trace_id)
    }

    /// Insert a TraceEvent into index_db - same as tracer_sidecar
    fn insert_trace_event(&mut self, event: &TraceEvent) -> Result<()> {
        // Use the SAME function as tracer_sidecar uses
        self.index_db.insert_trace_event_from_model(event)?;

        self.event_count += 1;

        Ok(())
    }

    /// Seal a window and write to RITMA_OUT
    pub fn seal_window(&mut self, start_ts: i64, end_ts: i64) -> Result<PathBuf> {
        // Get leaf hashes from recent events
        let leaf_hashes = self.get_leaf_hashes_for_window(start_ts, end_ts)?;

        if leaf_hashes.is_empty() {
            return Ok(self.contract.out_dir.clone());
        }

        // Write to RITMA_OUT using real contract
        self.contract.write_window_output(
            &self.namespace_id,
            start_ts,
            end_ts,
            leaf_hashes.len() as u64,
            &leaf_hashes,
        )?;

        info!(
            namespace = %self.namespace_id,
            events = leaf_hashes.len(),
            "Sealed window to RITMA_OUT"
        );

        Ok(self.contract.out_dir.clone())
    }

    fn get_leaf_hashes_for_window(&self, start_ts: i64, end_ts: i64) -> Result<Vec<[u8; 32]>> {
        // Get events from index_db and compute their hashes
        let events = self.index_db.list_trace_events_range(&self.namespace_id, start_ts, end_ts)?;
        
        let leaf_hashes: Vec<[u8; 32]> = events
            .iter()
            .map(|e| {
                let json = serde_json::to_string(e).unwrap_or_default();
                let hash = hash_string_sha256(&json);
                let bytes = hex::decode(&hash).unwrap_or_default();
                let mut arr = [0u8; 32];
                if bytes.len() == 32 {
                    arr.copy_from_slice(&bytes);
                }
                arr
            })
            .collect();

        Ok(leaf_hashes)
    }

    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    pub fn out_dir(&self) -> &PathBuf {
        &self.contract.out_dir
    }

    pub fn index_db_path(&self) -> &PathBuf {
        &self.contract.index_db_path
    }
}
