//! Graph-lite index spec (2.4)
//!
//! This module defines the edge types, hourly segment storage, and key format
//! for the lightweight graph index used for lineage queries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Edge types for the graph index
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EdgeType {
    /// Process execution lineage: parent -> child
    ExecLineage = 0,
    /// Process to file: proc -> file (read/write/exec)
    ProcToFile = 1,
    /// Process to network flow: proc -> flow
    ProcToFlow = 2,
    /// File to file: source -> dest (copy/rename)
    FileToFile = 3,
    /// Process to process: IPC/signal
    ProcToProc = 4,
    /// Container to process: container -> proc
    ContainerToProc = 5,
}

impl EdgeType {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ExecLineage),
            1 => Some(Self::ProcToFile),
            2 => Some(Self::ProcToFlow),
            3 => Some(Self::FileToFile),
            4 => Some(Self::ProcToProc),
            5 => Some(Self::ContainerToProc),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ExecLineage => "exec_lineage",
            Self::ProcToFile => "proc_file",
            Self::ProcToFlow => "proc_flow",
            Self::FileToFile => "file_file",
            Self::ProcToProc => "proc_proc",
            Self::ContainerToProc => "container_proc",
        }
    }
}

/// Edge flags for additional metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeFlags(pub u16);

impl EdgeFlags {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXEC: Self = Self(1 << 2);
    pub const DELETE: Self = Self(1 << 3);
    pub const CREATE: Self = Self(1 << 4);
    pub const RENAME: Self = Self(1 << 5);
    pub const SEND: Self = Self(1 << 6);
    pub const RECV: Self = Self(1 << 7);

    pub fn contains(&self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }
}

/// A graph edge record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub edge_type: EdgeType,
    pub src_id: u64,    // Dictionary ID of source node
    pub dst_id: u64,    // Dictionary ID of destination node
    pub timestamp: i64, // Unix timestamp (seconds)
    pub flags: EdgeFlags,
    pub weight: u32, // Edge weight/count for aggregation
}

impl Edge {
    pub fn new(edge_type: EdgeType, src_id: u64, dst_id: u64, timestamp: i64) -> Self {
        Self {
            edge_type,
            src_id,
            dst_id,
            timestamp,
            flags: EdgeFlags::NONE,
            weight: 1,
        }
    }

    pub fn with_flags(mut self, flags: EdgeFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Encode edge as compact key for storage
    /// Format: [edge_type:1][src_id:8][time_bucket:4][dst_id:8] = 21 bytes
    pub fn to_key(&self, time_bucket_secs: u32) -> [u8; 21] {
        let mut key = [0u8; 21];
        key[0] = self.edge_type.to_u8();
        key[1..9].copy_from_slice(&self.src_id.to_be_bytes());
        let bucket = (self.timestamp as u32) / time_bucket_secs;
        key[9..13].copy_from_slice(&bucket.to_be_bytes());
        key[13..21].copy_from_slice(&self.dst_id.to_be_bytes());
        key
    }

    /// Encode edge value for storage
    pub fn to_value(&self) -> Vec<u8> {
        let tuple = (self.timestamp, self.flags.0, self.weight);
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    /// CBOR tuple encoding for batch storage
    pub fn to_cbor_tuple(&self) -> Vec<u8> {
        let tuple = (
            self.edge_type.to_u8(),
            self.src_id,
            self.dst_id,
            self.timestamp,
            self.flags.0,
            self.weight,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Adjacency list for a source node
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdjacencyList {
    pub src_id: u64,
    pub edges: Vec<(u64, i64, u16, u32)>, // (dst_id, timestamp, flags, weight)
}

impl AdjacencyList {
    pub fn new(src_id: u64) -> Self {
        Self {
            src_id,
            edges: Vec::new(),
        }
    }

    pub fn add_edge(&mut self, dst_id: u64, timestamp: i64, flags: EdgeFlags, weight: u32) {
        self.edges.push((dst_id, timestamp, flags.0, weight));
    }

    pub fn to_packed(&self) -> Vec<u8> {
        let tuple = ("ritma-adj@0.1", self.src_id, &self.edges);
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Hourly edge segment writer
pub struct HourlyEdgeWriter {
    hour_dir: PathBuf,
    edges_by_type: HashMap<EdgeType, Vec<Edge>>,
    max_edges_per_flush: usize,
}

impl HourlyEdgeWriter {
    pub fn new(graph_dir: &Path, hour_ts: i64) -> std::io::Result<Self> {
        let dt = chrono::DateTime::from_timestamp(hour_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());

        let hour_dir = graph_dir
            .join("edges")
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()))
            .join(format!("{:02}", dt.hour()));

        std::fs::create_dir_all(&hour_dir)?;

        Ok(Self {
            hour_dir,
            edges_by_type: HashMap::new(),
            max_edges_per_flush: 10000,
        })
    }

    /// Add an edge to the buffer
    pub fn add_edge(&mut self, edge: Edge) -> std::io::Result<()> {
        let edges = self.edges_by_type.entry(edge.edge_type).or_default();
        edges.push(edge);

        // Auto-flush if buffer is full
        let total: usize = self.edges_by_type.values().map(|v| v.len()).sum();
        if total >= self.max_edges_per_flush {
            self.flush()?;
        }
        Ok(())
    }

    /// Flush all buffered edges to disk
    pub fn flush(&mut self) -> std::io::Result<()> {
        // Collect keys first to avoid borrow conflict
        let keys: Vec<EdgeType> = self.edges_by_type.keys().copied().collect();
        for edge_type in keys {
            if let Some(edges) = self.edges_by_type.remove(&edge_type) {
                if edges.is_empty() {
                    continue;
                }
                self.write_edge_segment(edge_type, &edges)?;
            }
        }
        Ok(())
    }

    fn write_edge_segment(&self, edge_type: EdgeType, edges: &[Edge]) -> std::io::Result<PathBuf> {
        let path = self
            .hour_dir
            .join(format!("{}.edges.cbor.zst", edge_type.name()));

        // Build adjacency lists grouped by src_id
        let mut adj_map: HashMap<u64, AdjacencyList> = HashMap::new();
        for e in edges {
            let adj = adj_map
                .entry(e.src_id)
                .or_insert_with(|| AdjacencyList::new(e.src_id));
            adj.add_edge(e.dst_id, e.timestamp, e.flags, e.weight);
        }

        let adj_lists: Vec<&AdjacencyList> = adj_map.values().collect();
        let tuple = (
            "ritma-edge-segment@0.1",
            edge_type.name(),
            edges.len(),
            adj_lists,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).map_err(std::io::Error::other)?;
        let compressed = zstd::encode_all(&buf[..], 0).map_err(std::io::Error::other)?;

        // Append to existing file or create new
        if path.exists() {
            // For simplicity, we overwrite; in production, merge would be better
            std::fs::write(&path, compressed)?;
        } else {
            std::fs::write(&path, compressed)?;
        }

        Ok(path)
    }

    /// Write edge refs index for the window
    pub fn write_edge_refs(&self, window_index_dir: &Path) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(window_index_dir)?;
        let path = window_index_dir.join("edge_refs.cbor");

        let edge_types: Vec<&str> = self.edges_by_type.keys().map(|t| t.name()).collect();

        let tuple = (
            "ritma-edge-refs@0.1",
            self.hour_dir.to_string_lossy().to_string(),
            edge_types,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).map_err(std::io::Error::other)?;
        std::fs::write(&path, buf)?;

        Ok(path)
    }
}

impl Drop for HourlyEdgeWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Graph query interface (read-only)
pub struct GraphReader {
    graph_dir: PathBuf,
}

impl GraphReader {
    pub fn new(graph_dir: &Path) -> Self {
        Self {
            graph_dir: graph_dir.to_path_buf(),
        }
    }

    /// Get all edges of a given type for a time range
    pub fn query_edges(
        &self,
        edge_type: EdgeType,
        start_ts: i64,
        end_ts: i64,
    ) -> std::io::Result<Vec<Edge>> {
        let mut edges = Vec::new();

        // Iterate over hour directories in range
        let mut ts = start_ts - (start_ts % 3600); // Round down to hour
        while ts < end_ts {
            if let Ok(hour_edges) = self.load_hour_edges(edge_type, ts) {
                for e in hour_edges {
                    if e.timestamp >= start_ts && e.timestamp < end_ts {
                        edges.push(e);
                    }
                }
            }
            ts += 3600;
        }

        Ok(edges)
    }

    fn load_hour_edges(&self, edge_type: EdgeType, hour_ts: i64) -> std::io::Result<Vec<Edge>> {
        let dt = chrono::DateTime::from_timestamp(hour_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());

        let path = self
            .graph_dir
            .join("edges")
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()))
            .join(format!("{:02}", dt.hour()))
            .join(format!("{}.edges.cbor.zst", edge_type.name()));

        if !path.exists() {
            return Ok(Vec::new());
        }

        let data = std::fs::read(&path)?;
        let decompressed = zstd::decode_all(&data[..]).map_err(std::io::Error::other)?;

        // Parse the segment
        let v: ciborium::value::Value =
            ciborium::from_reader(&decompressed[..]).map_err(std::io::Error::other)?;

        self.parse_edge_segment(edge_type, &v)
    }

    fn parse_edge_segment(
        &self,
        edge_type: EdgeType,
        v: &ciborium::value::Value,
    ) -> std::io::Result<Vec<Edge>> {
        let ciborium::value::Value::Array(arr) = v else {
            return Ok(Vec::new());
        };
        if arr.len() < 4 {
            return Ok(Vec::new());
        }

        // arr[3] is the adjacency lists
        let Some(ciborium::value::Value::Array(adj_lists)) = arr.get(3) else {
            return Ok(Vec::new());
        };

        let mut edges = Vec::new();
        for adj in adj_lists {
            let ciborium::value::Value::Array(adj_arr) = adj else {
                continue;
            };
            if adj_arr.len() < 3 {
                continue;
            }

            // Parse src_id
            let src_id = match adj_arr.get(1) {
                Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
                _ => continue,
            };

            // Parse edges array
            let Some(ciborium::value::Value::Array(edge_arr)) = adj_arr.get(2) else {
                continue;
            };

            for edge_tuple in edge_arr {
                let ciborium::value::Value::Array(et) = edge_tuple else {
                    continue;
                };
                if et.len() < 4 {
                    continue;
                }

                let dst_id = match et.get(0) {
                    Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
                    _ => continue,
                };
                let timestamp = match et.get(1) {
                    Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
                    _ => continue,
                };
                let flags = match et.get(2) {
                    Some(ciborium::value::Value::Integer(i)) => {
                        EdgeFlags((*i).try_into().unwrap_or(0))
                    }
                    _ => EdgeFlags::NONE,
                };
                let weight = match et.get(3) {
                    Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(1),
                    _ => 1,
                };

                edges.push(Edge {
                    edge_type,
                    src_id,
                    dst_id,
                    timestamp,
                    flags,
                    weight,
                });
            }
        }

        Ok(edges)
    }

    /// Get forward neighbors (outgoing edges) for a node
    pub fn get_neighbors(
        &self,
        edge_type: EdgeType,
        src_id: u64,
        start_ts: i64,
        end_ts: i64,
    ) -> std::io::Result<Vec<(u64, i64)>> {
        let edges = self.query_edges(edge_type, start_ts, end_ts)?;
        Ok(edges
            .into_iter()
            .filter(|e| e.src_id == src_id)
            .map(|e| (e.dst_id, e.timestamp))
            .collect())
    }

    /// Get reverse neighbors (incoming edges) for a node
    pub fn get_reverse_neighbors(
        &self,
        edge_type: EdgeType,
        dst_id: u64,
        start_ts: i64,
        end_ts: i64,
    ) -> std::io::Result<Vec<(u64, i64)>> {
        let edges = self.query_edges(edge_type, start_ts, end_ts)?;
        Ok(edges
            .into_iter()
            .filter(|e| e.dst_id == dst_id)
            .map(|e| (e.src_id, e.timestamp))
            .collect())
    }
}

use chrono::Datelike;
use chrono::Timelike;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_key_encoding() {
        let edge = Edge::new(EdgeType::ExecLineage, 100, 200, 1704067200);
        let key = edge.to_key(3600); // 1-hour buckets
        assert_eq!(key[0], EdgeType::ExecLineage.to_u8());
    }

    #[test]
    fn edge_flags() {
        let mut flags = EdgeFlags::NONE;
        flags.set(EdgeFlags::READ);
        flags.set(EdgeFlags::WRITE);
        assert!(flags.contains(EdgeFlags::READ));
        assert!(flags.contains(EdgeFlags::WRITE));
        assert!(!flags.contains(EdgeFlags::EXEC));
    }

    #[test]
    fn adjacency_list_packing() {
        let mut adj = AdjacencyList::new(42);
        adj.add_edge(100, 1000, EdgeFlags::READ, 1);
        adj.add_edge(200, 2000, EdgeFlags::WRITE, 2);
        let packed = adj.to_packed();
        assert!(!packed.is_empty());
    }

    #[test]
    fn edge_type_roundtrip() {
        for et in [
            EdgeType::ExecLineage,
            EdgeType::ProcToFile,
            EdgeType::ProcToFlow,
        ] {
            assert_eq!(EdgeType::from_u8(et.to_u8()), Some(et));
        }
    }
}
