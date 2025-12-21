// Log Camera - CCTV-Style Snapshot System for Immutable Evidence
// Captures "frames" of system state transitions with full audit trail

use serde::{Deserialize, Serialize};
use core_types::{Hash, hash_bytes, UID};
use clock::TimeTick;
use std::collections::HashMap;

/// A single "frame" captured by the log camera
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFrame {
    /// Unique frame ID
    pub frame_id: UID,
    
    /// Frame number in sequence
    pub frame_number: u64,
    
    /// Timestamp when frame was captured
    pub timestamp: TimeTick,
    
    /// State snapshot at this frame
    pub state_snapshot: StateSnapshot,
    
    /// Transition that led to this frame
    pub transition: Option<Transition>,
    
    /// Hash of previous frame (chain)
    pub prev_frame_hash: Option<Hash>,
    
    /// Hash of this frame
    pub frame_hash: Hash,
    
    /// Merkle root of all events in this frame
    pub events_merkle_root: Hash,
}

/// Complete state snapshot at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Active DIDs in system
    pub active_dids: Vec<String>,
    
    /// Active policies
    pub active_policies: Vec<String>,
    
    /// Resource states (cgroups, eBPF, network)
    pub resource_states: HashMap<String, ResourceState>,
    
    /// Pending decisions
    pub pending_decisions: Vec<String>,
    
    /// System metrics
    pub metrics: SystemMetrics,
}

/// State of a system resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceState {
    pub resource_type: String,
    pub resource_id: String,
    pub status: String,
    pub config_hash: Hash,
    pub last_modified: u64,
}

/// System metrics at snapshot time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: u64,
    pub network_bytes_in: u64,
    pub network_bytes_out: u64,
    pub active_connections: u32,
    pub decision_count: u64,
}

/// A state transition between frames
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    /// Transition ID
    pub transition_id: UID,
    
    /// Type of transition
    pub transition_type: TransitionType,
    
    /// Actor who triggered transition
    pub actor_did: Option<String>,
    
    /// Events that occurred during transition
    pub events: Vec<TransitionEvent>,
    
    /// Before state hash
    pub before_hash: Hash,
    
    /// After state hash
    pub after_hash: Hash,
    
    /// Transition duration (microseconds)
    pub duration_us: u64,
}

/// Types of state transitions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionType {
    /// Policy decision made
    PolicyDecision,
    /// Resource allocated/modified
    ResourceChange,
    /// DID authenticated
    DidAuth,
    /// Service started/stopped
    ServiceLifecycle,
    /// Consensus reached
    ConsensusReached,
    /// Compliance burn created
    ComplianceBurn,
    /// eBPF program loaded/unloaded
    EbpfChange,
    /// Network rule changed
    NetworkRuleChange,
}

/// Event within a transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionEvent {
    pub event_type: String,
    pub event_data: serde_json::Value,
    pub timestamp_us: u64,
    pub event_hash: Hash,
}

/// Log Camera - captures and stores frames
pub struct LogCamera {
    /// Camera ID
    camera_id: UID,
    
    /// Current frame number
    frame_number: u64,
    
    /// Frames buffer (in-memory before flush)
    frames_buffer: Vec<LogFrame>,
    
    /// Last frame hash (for chaining)
    last_frame_hash: Option<Hash>,
    
    /// Frame rate (frames per second)
    frame_rate_fps: u32,
    
    /// Last capture time
    last_capture_us: u64,
}

impl LogCamera {
    pub fn new(camera_id: UID, frame_rate_fps: u32) -> Self {
        Self {
            camera_id,
            frame_number: 0,
            frames_buffer: Vec::new(),
            last_frame_hash: None,
            frame_rate_fps,
            last_capture_us: 0,
        }
    }

    /// Capture a new frame
    pub fn capture_frame(
        &mut self,
        timestamp: TimeTick,
        state: StateSnapshot,
        transition: Option<Transition>,
    ) -> LogFrame {
        let frame_id = UID::new();
        self.frame_number += 1;

        // Compute events Merkle root
        let events_merkle_root = if let Some(ref t) = transition {
            compute_events_merkle_root(&t.events)
        } else {
            hash_bytes(&[])
        };

        let mut frame = LogFrame {
            frame_id,
            frame_number: self.frame_number,
            timestamp,
            state_snapshot: state,
            transition,
            prev_frame_hash: self.last_frame_hash.clone(),
            frame_hash: Hash([0u8; 32]), // Computed below
            events_merkle_root,
        };

        // Compute frame hash
        frame.frame_hash = compute_frame_hash(&frame);
        self.last_frame_hash = Some(frame.frame_hash.clone());

        // Add to buffer
        self.frames_buffer.push(frame.clone());

        frame
    }

    /// Check if it's time to capture based on frame rate
    pub fn should_capture(&self, current_time_us: u64) -> bool {
        if self.last_capture_us == 0 {
            return true;
        }

        let interval_us = 1_000_000 / self.frame_rate_fps as u64;
        current_time_us - self.last_capture_us >= interval_us
    }

    /// Flush frames to storage
    pub fn flush_frames(&mut self) -> Vec<LogFrame> {
        let frames = self.frames_buffer.clone();
        self.frames_buffer.clear();
        frames
    }

    /// Get current frame count
    pub fn frame_count(&self) -> u64 {
        self.frame_number
    }

    /// Verify frame chain integrity
    pub fn verify_frames(frames: &[LogFrame]) -> Result<(), String> {
        if frames.is_empty() {
            return Ok(());
        }

        // First frame should have no prev_frame_hash
        if frames[0].prev_frame_hash.is_some() {
            return Err("First frame should not have prev_frame_hash".to_string());
        }

        // Verify each frame's hash
        for frame in frames {
            let computed = compute_frame_hash(frame);
            if computed.0 != frame.frame_hash.0 {
                return Err(format!("Frame {} hash mismatch", frame.frame_number));
            }
        }

        // Verify chain linkage
        for i in 1..frames.len() {
            let prev_hash = frames[i - 1].frame_hash.clone();
            let current_prev = frames[i].prev_frame_hash.clone()
                .ok_or_else(|| format!("Frame {} missing prev_frame_hash", i))?;
            
            if prev_hash.0 != current_prev.0 {
                return Err(format!("Chain broken at frame {}", i));
            }
        }

        Ok(())
    }
}

/// Compute hash of a frame
fn compute_frame_hash(frame: &LogFrame) -> Hash {
    let mut buffer = Vec::new();
    
    // Frame metadata
    buffer.extend_from_slice(&frame.frame_id.0.to_le_bytes());
    buffer.extend_from_slice(&frame.frame_number.to_le_bytes());
    buffer.extend_from_slice(&frame.timestamp.raw_time.to_le_bytes());
    
    // Previous frame hash
    if let Some(ref prev) = frame.prev_frame_hash {
        buffer.extend_from_slice(&prev.0);
    }
    
    // Events merkle root
    buffer.extend_from_slice(&frame.events_merkle_root.0);
    
    // State snapshot hash
    let state_json = serde_json::to_string(&frame.state_snapshot).unwrap_or_default();
    buffer.extend_from_slice(state_json.as_bytes());
    
    // Transition hash
    if let Some(ref t) = frame.transition {
        buffer.extend_from_slice(&t.transition_id.0.to_le_bytes());
        buffer.extend_from_slice(&t.before_hash.0);
        buffer.extend_from_slice(&t.after_hash.0);
    }
    
    hash_bytes(&buffer)
}

/// Compute Merkle root of transition events
fn compute_events_merkle_root(events: &[TransitionEvent]) -> Hash {
    if events.is_empty() {
        return hash_bytes(&[]);
    }

    let leaves: Vec<[u8; 32]> = events
        .iter()
        .map(|e| e.event_hash.0)
        .collect();

    use rs_merkle::{algorithms::Sha256, MerkleTree};
    let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = tree.root().unwrap_or([0u8; 32]);
    Hash(root)
}

/// Log Camera Recorder - manages multiple cameras and storage
pub struct LogCameraRecorder {
    cameras: HashMap<String, LogCamera>,
    storage_path: String,
}

impl LogCameraRecorder {
    pub fn new(storage_path: String) -> Self {
        Self {
            cameras: HashMap::new(),
            storage_path,
        }
    }

    /// Register a new camera
    pub fn register_camera(&mut self, name: String, frame_rate_fps: u32) -> UID {
        let camera_id = UID::new();
        let camera = LogCamera::new(camera_id, frame_rate_fps);
        self.cameras.insert(name, camera);
        camera_id
    }

    /// Capture frame on specific camera
    pub fn capture(
        &mut self,
        camera_name: &str,
        timestamp: TimeTick,
        state: StateSnapshot,
        transition: Option<Transition>,
    ) -> Result<LogFrame, String> {
        let camera = self.cameras.get_mut(camera_name)
            .ok_or_else(|| format!("Camera {} not found", camera_name))?;
        
        Ok(camera.capture_frame(timestamp, state, transition))
    }

    /// Flush all cameras to disk
    pub fn flush_all(&mut self) -> Result<usize, String> {
        let mut total_frames = 0;
        let camera_names: Vec<String> = self.cameras.keys().cloned().collect();
        
        for name in camera_names {
            if let Some(camera) = self.cameras.get_mut(&name) {
                let frames = camera.flush_frames();
                if !frames.is_empty() {
                    self.write_frames_to_disk(&name, &frames)?;
                    total_frames += frames.len();
                }
            }
        }
        
        Ok(total_frames)
    }

    /// Write frames to disk
    fn write_frames_to_disk(&self, camera_name: &str, frames: &[LogFrame]) -> Result<(), String> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let filename = format!("{}/{}_frames.jsonl", self.storage_path, camera_name);
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filename)
            .map_err(|e| format!("Failed to open file: {}", e))?;

        for frame in frames {
            let json = serde_json::to_string(frame)
                .map_err(|e| format!("Failed to serialize frame: {}", e))?;
            file.write_all(json.as_bytes())
                .map_err(|e| format!("Failed to write frame: {}", e))?;
            file.write_all(b"\n")
                .map_err(|e| format!("Failed to write newline: {}", e))?;
        }

        file.flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_state() -> StateSnapshot {
        StateSnapshot {
            active_dids: vec!["did:ritma:user:alice".to_string()],
            active_policies: vec!["policy_v1".to_string()],
            resource_states: HashMap::new(),
            pending_decisions: vec![],
            metrics: SystemMetrics {
                cpu_usage_percent: 45.0,
                memory_usage_mb: 1024,
                network_bytes_in: 1000,
                network_bytes_out: 500,
                active_connections: 5,
                decision_count: 100,
            },
        }
    }

    #[test]
    fn log_camera_captures_frames() {
        let mut camera = LogCamera::new(UID::new(), 10);
        
        let frame = camera.capture_frame(
            TimeTick { raw_time: 100, mock_time: 100.0 },
            create_test_state(),
            None,
        );

        assert_eq!(frame.frame_number, 1);
        assert!(frame.prev_frame_hash.is_none());
    }

    #[test]
    fn log_camera_chains_frames() {
        let mut camera = LogCamera::new(UID::new(), 10);
        
        let frame1 = camera.capture_frame(
            TimeTick { raw_time: 100, mock_time: 100.0 },
            create_test_state(),
            None,
        );

        let frame2 = camera.capture_frame(
            TimeTick { raw_time: 200, mock_time: 200.0 },
            create_test_state(),
            None,
        );

        assert_eq!(frame2.prev_frame_hash, Some(frame1.frame_hash.clone()));
    }

    #[test]
    fn verify_frames_validates_chain() {
        let mut camera = LogCamera::new(UID::new(), 10);
        
        let frame1 = camera.capture_frame(
            TimeTick { raw_time: 100, mock_time: 100.0 },
            create_test_state(),
            None,
        );

        let frame2 = camera.capture_frame(
            TimeTick { raw_time: 200, mock_time: 200.0 },
            create_test_state(),
            None,
        );

        let frames = vec![frame1, frame2];
        assert!(LogCamera::verify_frames(&frames).is_ok());
    }

    #[test]
    fn recorder_manages_multiple_cameras() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut recorder = LogCameraRecorder::new(temp_dir.path().to_string_lossy().to_string());

        recorder.register_camera("main".to_string(), 10);
        recorder.register_camera("audit".to_string(), 5);

        let frame = recorder.capture(
            "main",
            TimeTick { raw_time: 100, mock_time: 100.0 },
            create_test_state(),
            None,
        );

        assert!(frame.is_ok());
    }
}
