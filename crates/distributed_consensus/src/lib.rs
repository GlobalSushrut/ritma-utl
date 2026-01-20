//! Distributed Consensus for Audit Log Replication (Q1.6)
//!
//! Implements Raft-based consensus for:
//! - Audit log replication across nodes
//! - Leader election
//! - Log consistency guarantees
//! - Snapshot transfer

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("not leader")]
    NotLeader,
    #[error("term mismatch: expected {0}, got {1}")]
    TermMismatch(u64, u64),
    #[error("log inconsistency at index {0}")]
    LogInconsistency(u64),
    #[error("node not found: {0}")]
    NodeNotFound(String),
    #[error("quorum not reached")]
    QuorumNotReached,
    #[error("timeout")]
    Timeout,
}

/// Node state in Raft
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeState {
    Follower,
    Candidate,
    Leader,
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub command: Command,
    pub timestamp: i64,
    pub entry_hash: [u8; 32],
}

impl LogEntry {
    pub fn new(index: u64, term: u64, command: Command) -> Self {
        let timestamp = chrono::Utc::now().timestamp();
        let entry_hash = Self::compute_hash(index, term, &command, timestamp);
        Self {
            index,
            term,
            command,
            timestamp,
            entry_hash,
        }
    }

    fn compute_hash(index: u64, term: u64, command: &Command, timestamp: i64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-raft-entry@0.1");
        h.update(index.to_le_bytes());
        h.update(term.to_le_bytes());
        h.update(timestamp.to_le_bytes());
        h.update(
            serde_json::to_string(command)
                .unwrap_or_default()
                .as_bytes(),
        );
        h.finalize().into()
    }

    pub fn entry_hash_hex(&self) -> String {
        hex::encode(self.entry_hash)
    }
}

/// Command to replicate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// Append audit event
    AppendEvent {
        event_id: String,
        event_hash: String,
    },
    /// Seal window
    SealWindow {
        window_id: String,
        merkle_root: String,
    },
    /// Register node
    RegisterNode { node_id: String, address: String },
    /// Deregister node
    DeregisterNode { node_id: String },
    /// No-op (for leader election)
    Noop,
}

/// RequestVote RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVote {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

/// AppendEntries RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntries {
    pub term: u64,
    pub leader_id: String,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>,
    pub leader_commit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
}

/// InstallSnapshot RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshot {
    pub term: u64,
    pub leader_id: String,
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub offset: u64,
    pub data: Vec<u8>,
    pub done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotResponse {
    pub term: u64,
}

/// Peer node info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNode {
    pub node_id: String,
    pub address: String,
    pub next_index: u64,
    pub match_index: u64,
    pub last_contact: i64,
}

/// Raft node
pub struct RaftNode {
    // Persistent state
    node_id: String,
    current_term: u64,
    voted_for: Option<String>,
    log: Vec<LogEntry>,

    // Volatile state
    state: NodeState,
    commit_index: u64,
    last_applied: u64,

    // Leader state
    peers: HashMap<String, PeerNode>,

    // Timing
    election_timeout_ms: u64,
    heartbeat_interval_ms: u64,
    last_heartbeat: i64,

    // Callbacks
    applied_commands: VecDeque<(u64, Command)>,
}

impl RaftNode {
    pub fn new(node_id: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
            state: NodeState::Follower,
            commit_index: 0,
            last_applied: 0,
            peers: HashMap::new(),
            election_timeout_ms: 150 + (node_id.len() as u64 * 50) % 150, // 150-300ms
            heartbeat_interval_ms: 50,
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            applied_commands: VecDeque::new(),
        }
    }

    /// Add peer node
    pub fn add_peer(&mut self, node_id: &str, address: &str) {
        self.peers.insert(
            node_id.to_string(),
            PeerNode {
                node_id: node_id.to_string(),
                address: address.to_string(),
                next_index: self.log.len() as u64 + 1,
                match_index: 0,
                last_contact: 0,
            },
        );
    }

    /// Get current state
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// Get current term
    pub fn current_term(&self) -> u64 {
        self.current_term
    }

    /// Check if this node is leader
    pub fn is_leader(&self) -> bool {
        self.state == NodeState::Leader
    }

    /// Get leader ID (if known)
    pub fn leader_id(&self) -> Option<&str> {
        if self.is_leader() {
            Some(&self.node_id)
        } else {
            self.voted_for.as_deref()
        }
    }

    /// Propose a command (leader only)
    pub fn propose(&mut self, command: Command) -> Result<u64, ConsensusError> {
        if !self.is_leader() {
            return Err(ConsensusError::NotLeader);
        }

        let index = self.log.len() as u64 + 1;
        let entry = LogEntry::new(index, self.current_term, command);
        self.log.push(entry);

        Ok(index)
    }

    /// Handle RequestVote RPC
    pub fn handle_request_vote(&mut self, request: RequestVote) -> RequestVoteResponse {
        // Update term if needed
        if request.term > self.current_term {
            self.current_term = request.term;
            self.voted_for = None;
            self.state = NodeState::Follower;
        }

        // Reject if term is old
        if request.term < self.current_term {
            return RequestVoteResponse {
                term: self.current_term,
                vote_granted: false,
            };
        }

        // Check if we can vote for this candidate
        let can_vote =
            self.voted_for.is_none() || self.voted_for.as_ref() == Some(&request.candidate_id);

        // Check if candidate's log is at least as up-to-date
        let last_log_term = self.log.last().map(|e| e.term).unwrap_or(0);
        let last_log_index = self.log.len() as u64;

        let log_ok = request.last_log_term > last_log_term
            || (request.last_log_term == last_log_term && request.last_log_index >= last_log_index);

        let vote_granted = can_vote && log_ok;

        if vote_granted {
            self.voted_for = Some(request.candidate_id);
            self.last_heartbeat = chrono::Utc::now().timestamp_millis();
        }

        RequestVoteResponse {
            term: self.current_term,
            vote_granted,
        }
    }

    /// Handle AppendEntries RPC
    pub fn handle_append_entries(&mut self, request: AppendEntries) -> AppendEntriesResponse {
        // Update term if needed
        if request.term > self.current_term {
            self.current_term = request.term;
            self.voted_for = None;
            self.state = NodeState::Follower;
        }

        // Reject if term is old
        if request.term < self.current_term {
            return AppendEntriesResponse {
                term: self.current_term,
                success: false,
                match_index: 0,
            };
        }

        // Reset election timeout
        self.last_heartbeat = chrono::Utc::now().timestamp_millis();
        self.state = NodeState::Follower;

        // Check log consistency
        if request.prev_log_index > 0 {
            let prev_entry = self.log.get(request.prev_log_index as usize - 1);
            match prev_entry {
                None => {
                    return AppendEntriesResponse {
                        term: self.current_term,
                        success: false,
                        match_index: self.log.len() as u64,
                    };
                }
                Some(entry) if entry.term != request.prev_log_term => {
                    // Delete conflicting entries
                    self.log.truncate(request.prev_log_index as usize - 1);
                    return AppendEntriesResponse {
                        term: self.current_term,
                        success: false,
                        match_index: self.log.len() as u64,
                    };
                }
                _ => {}
            }
        }

        // Append new entries
        for entry in request.entries {
            let idx = entry.index as usize - 1;
            if idx < self.log.len() {
                if self.log[idx].term != entry.term {
                    self.log.truncate(idx);
                    self.log.push(entry);
                }
            } else {
                self.log.push(entry);
            }
        }

        // Update commit index
        if request.leader_commit > self.commit_index {
            self.commit_index = request.leader_commit.min(self.log.len() as u64);
            self.apply_committed();
        }

        AppendEntriesResponse {
            term: self.current_term,
            success: true,
            match_index: self.log.len() as u64,
        }
    }

    /// Apply committed entries
    fn apply_committed(&mut self) {
        while self.last_applied < self.commit_index {
            self.last_applied += 1;
            if let Some(entry) = self.log.get(self.last_applied as usize - 1) {
                self.applied_commands
                    .push_back((entry.index, entry.command.clone()));
            }
        }
    }

    /// Get applied commands (and clear queue)
    pub fn drain_applied(&mut self) -> Vec<(u64, Command)> {
        self.applied_commands.drain(..).collect()
    }

    /// Start election
    pub fn start_election(&mut self) -> RequestVote {
        self.current_term += 1;
        self.state = NodeState::Candidate;
        self.voted_for = Some(self.node_id.clone());
        self.last_heartbeat = chrono::Utc::now().timestamp_millis();

        RequestVote {
            term: self.current_term,
            candidate_id: self.node_id.clone(),
            last_log_index: self.log.len() as u64,
            last_log_term: self.log.last().map(|e| e.term).unwrap_or(0),
        }
    }

    /// Handle vote response
    pub fn handle_vote_response(&mut self, response: RequestVoteResponse, votes_received: usize) {
        if response.term > self.current_term {
            self.current_term = response.term;
            self.state = NodeState::Follower;
            self.voted_for = None;
            return;
        }

        if self.state != NodeState::Candidate {
            return;
        }

        // Check if we have majority
        let total_nodes = self.peers.len() + 1;
        let majority = total_nodes / 2 + 1;

        if votes_received >= majority {
            self.become_leader();
        }
    }

    /// Become leader
    fn become_leader(&mut self) {
        self.state = NodeState::Leader;

        // Initialize peer indices
        let next_index = self.log.len() as u64 + 1;
        for peer in self.peers.values_mut() {
            peer.next_index = next_index;
            peer.match_index = 0;
        }

        // Append no-op entry
        let _ = self.propose(Command::Noop);
    }

    /// Create heartbeat (empty AppendEntries)
    pub fn create_heartbeat(&self) -> Option<AppendEntries> {
        if !self.is_leader() {
            return None;
        }

        Some(AppendEntries {
            term: self.current_term,
            leader_id: self.node_id.clone(),
            prev_log_index: self.log.len() as u64,
            prev_log_term: self.log.last().map(|e| e.term).unwrap_or(0),
            entries: Vec::new(),
            leader_commit: self.commit_index,
        })
    }

    /// Create AppendEntries for a specific peer
    pub fn create_append_entries(&self, peer_id: &str) -> Option<AppendEntries> {
        if !self.is_leader() {
            return None;
        }

        let peer = self.peers.get(peer_id)?;
        let prev_log_index = peer.next_index - 1;
        let prev_log_term = if prev_log_index > 0 {
            self.log
                .get(prev_log_index as usize - 1)
                .map(|e| e.term)
                .unwrap_or(0)
        } else {
            0
        };

        let entries: Vec<LogEntry> = self
            .log
            .iter()
            .skip(peer.next_index as usize - 1)
            .take(100) // Batch size
            .cloned()
            .collect();

        Some(AppendEntries {
            term: self.current_term,
            leader_id: self.node_id.clone(),
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit: self.commit_index,
        })
    }

    /// Handle AppendEntries response from peer
    pub fn handle_append_response(&mut self, peer_id: &str, response: AppendEntriesResponse) {
        if response.term > self.current_term {
            self.current_term = response.term;
            self.state = NodeState::Follower;
            self.voted_for = None;
            return;
        }

        if !self.is_leader() {
            return;
        }

        if let Some(peer) = self.peers.get_mut(peer_id) {
            if response.success {
                peer.match_index = response.match_index;
                peer.next_index = response.match_index + 1;
                peer.last_contact = chrono::Utc::now().timestamp();

                // Update commit index
                self.update_commit_index();
            } else {
                // Decrement next_index and retry
                peer.next_index = peer.next_index.saturating_sub(1).max(1);
            }
        }
    }

    /// Update commit index based on peer match indices
    fn update_commit_index(&mut self) {
        let mut match_indices: Vec<u64> = self.peers.values().map(|p| p.match_index).collect();
        match_indices.push(self.log.len() as u64); // Include self
        match_indices.sort_unstable();

        let majority_idx = match_indices.len() / 2;
        let new_commit = match_indices[majority_idx];

        if new_commit > self.commit_index {
            // Only commit entries from current term
            if let Some(entry) = self.log.get(new_commit as usize - 1) {
                if entry.term == self.current_term {
                    self.commit_index = new_commit;
                    self.apply_committed();
                }
            }
        }
    }

    /// Check if election timeout has elapsed
    pub fn election_timeout_elapsed(&self) -> bool {
        if self.state == NodeState::Leader {
            return false;
        }

        let now = chrono::Utc::now().timestamp_millis();
        (now - self.last_heartbeat) as u64 > self.election_timeout_ms
    }

    /// Check if heartbeat is due
    pub fn heartbeat_due(&self) -> bool {
        if !self.is_leader() {
            return false;
        }

        let now = chrono::Utc::now().timestamp_millis();
        (now - self.last_heartbeat) as u64 > self.heartbeat_interval_ms
    }

    /// Get log length
    pub fn log_len(&self) -> usize {
        self.log.len()
    }

    /// Get commit index
    pub fn commit_index(&self) -> u64 {
        self.commit_index
    }

    /// Get node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Get peer IDs
    pub fn peer_ids(&self) -> Vec<&str> {
        self.peers.keys().map(|s| s.as_str()).collect()
    }
}

/// Consensus cluster manager
pub struct ConsensusCluster {
    nodes: HashMap<String, RaftNode>,
    message_queue: VecDeque<ClusterMessage>,
}

#[derive(Debug, Clone)]
pub enum ClusterMessage {
    RequestVote {
        from: String,
        to: String,
        request: RequestVote,
    },
    RequestVoteResponse {
        from: String,
        to: String,
        response: RequestVoteResponse,
    },
    AppendEntries {
        from: String,
        to: String,
        request: AppendEntries,
    },
    AppendEntriesResponse {
        from: String,
        to: String,
        response: AppendEntriesResponse,
    },
}

impl ConsensusCluster {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            message_queue: VecDeque::new(),
        }
    }

    /// Add node to cluster
    pub fn add_node(&mut self, node_id: &str) {
        let mut node = RaftNode::new(node_id);

        // Add all existing nodes as peers
        for existing_id in self.nodes.keys() {
            node.add_peer(existing_id, &format!("{}:8080", existing_id));
        }

        // Add new node as peer to all existing nodes
        for existing_node in self.nodes.values_mut() {
            existing_node.add_peer(node_id, &format!("{}:8080", node_id));
        }

        self.nodes.insert(node_id.to_string(), node);
    }

    /// Propose command to cluster
    pub fn propose(&mut self, command: Command) -> Result<u64, ConsensusError> {
        // Find leader
        let leader_id = self
            .nodes
            .values()
            .find(|n| n.is_leader())
            .map(|n| n.node_id().to_string())
            .ok_or(ConsensusError::NotLeader)?;

        let node = self.nodes.get_mut(&leader_id).unwrap();
        let index = node.propose(command)?;

        // Queue AppendEntries to all peers
        for peer_id in node.peer_ids() {
            if let Some(request) = node.create_append_entries(peer_id) {
                self.message_queue.push_back(ClusterMessage::AppendEntries {
                    from: leader_id.clone(),
                    to: peer_id.to_string(),
                    request,
                });
            }
        }

        Ok(index)
    }

    /// Process one message from queue
    pub fn process_message(&mut self) -> bool {
        let msg = match self.message_queue.pop_front() {
            Some(m) => m,
            None => return false,
        };

        match msg {
            ClusterMessage::RequestVote { from, to, request } => {
                if let Some(node) = self.nodes.get_mut(&to) {
                    let response = node.handle_request_vote(request);
                    self.message_queue
                        .push_back(ClusterMessage::RequestVoteResponse {
                            from: to,
                            to: from,
                            response,
                        });
                }
            }
            ClusterMessage::RequestVoteResponse { from, to, response } => {
                if let Some(node) = self.nodes.get_mut(&to) {
                    // Count votes (simplified)
                    let votes = if response.vote_granted { 2 } else { 1 };
                    node.handle_vote_response(response, votes);
                }
            }
            ClusterMessage::AppendEntries { from, to, request } => {
                if let Some(node) = self.nodes.get_mut(&to) {
                    let response = node.handle_append_entries(request);
                    self.message_queue
                        .push_back(ClusterMessage::AppendEntriesResponse {
                            from: to,
                            to: from,
                            response,
                        });
                }
            }
            ClusterMessage::AppendEntriesResponse { from, to, response } => {
                if let Some(node) = self.nodes.get_mut(&to) {
                    node.handle_append_response(&from, response);
                }
            }
        }

        true
    }

    /// Tick all nodes (check timeouts)
    pub fn tick(&mut self) {
        let node_ids: Vec<String> = self.nodes.keys().cloned().collect();

        for node_id in node_ids {
            let node = self.nodes.get_mut(&node_id).unwrap();

            if node.election_timeout_elapsed() {
                let request = node.start_election();
                let peer_ids: Vec<String> = node.peer_ids().iter().map(|s| s.to_string()).collect();

                for peer_id in peer_ids {
                    self.message_queue.push_back(ClusterMessage::RequestVote {
                        from: node_id.clone(),
                        to: peer_id,
                        request: request.clone(),
                    });
                }
            } else if node.heartbeat_due() {
                if let Some(heartbeat) = node.create_heartbeat() {
                    let peer_ids: Vec<String> =
                        node.peer_ids().iter().map(|s| s.to_string()).collect();

                    for peer_id in peer_ids {
                        self.message_queue.push_back(ClusterMessage::AppendEntries {
                            from: node_id.clone(),
                            to: peer_id,
                            request: heartbeat.clone(),
                        });
                    }
                }
            }
        }
    }

    /// Get leader node ID
    pub fn leader_id(&self) -> Option<&str> {
        self.nodes
            .values()
            .find(|n| n.is_leader())
            .map(|n| n.node_id())
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get applied commands from all nodes
    pub fn drain_applied(&mut self) -> Vec<(String, u64, Command)> {
        let mut all_applied = Vec::new();
        for (node_id, node) in &mut self.nodes {
            for (index, cmd) in node.drain_applied() {
                all_applied.push((node_id.clone(), index, cmd));
            }
        }
        all_applied
    }
}

impl Default for ConsensusCluster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raft_node_creation() {
        let node = RaftNode::new("node1");
        assert_eq!(node.state(), NodeState::Follower);
        assert_eq!(node.current_term(), 0);
        assert!(!node.is_leader());
    }

    #[test]
    fn test_request_vote() {
        let mut node = RaftNode::new("node1");

        let request = RequestVote {
            term: 1,
            candidate_id: "node2".to_string(),
            last_log_index: 0,
            last_log_term: 0,
        };

        let response = node.handle_request_vote(request);
        assert!(response.vote_granted);
        assert_eq!(node.current_term(), 1);
    }

    #[test]
    fn test_append_entries() {
        let mut node = RaftNode::new("node1");

        let request = AppendEntries {
            term: 1,
            leader_id: "leader".to_string(),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![LogEntry::new(1, 1, Command::Noop)],
            leader_commit: 0,
        };

        let response = node.handle_append_entries(request);
        assert!(response.success);
        assert_eq!(node.log_len(), 1);
    }

    #[test]
    fn test_cluster_election() {
        // Test single node becoming leader directly
        let mut node = RaftNode::new("node1");
        node.add_peer("node2", "node2:8080");

        // Start election
        let _request = node.start_election();

        // Simulate receiving vote
        let response = RequestVoteResponse {
            term: 1,
            vote_granted: true,
        };
        node.handle_vote_response(response, 2); // 2 votes (self + 1)

        // Should be leader now
        assert!(node.is_leader());
    }

    #[test]
    fn test_log_replication() {
        // Test log replication between two nodes
        let mut leader = RaftNode::new("leader");
        leader.add_peer("follower", "follower:8080");

        // Make leader
        let _request = leader.start_election();
        leader.handle_vote_response(
            RequestVoteResponse {
                term: 1,
                vote_granted: true,
            },
            2,
        );
        assert!(leader.is_leader());

        // Propose command
        let result = leader.propose(Command::AppendEvent {
            event_id: "evt1".to_string(),
            event_hash: "hash1".to_string(),
        });
        assert!(result.is_ok());

        // Create follower and replicate
        let mut follower = RaftNode::new("follower");
        follower.add_peer("leader", "leader:8080");

        let append_req = leader.create_append_entries("follower").unwrap();
        let response = follower.handle_append_entries(append_req);

        assert!(response.success);
        assert_eq!(follower.log_len(), 2); // noop + event
    }
}
