//! Causal ordering primitives for distributed event tracing
//!
//! Provides Lamport timestamps and vector clocks for establishing
//! happened-before relationships between events across nodes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Lamport clock for logical timestamps
#[derive(Debug)]
pub struct LamportClock {
    counter: AtomicU64,
}

impl LamportClock {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Get current timestamp without incrementing
    pub fn current(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Increment and return new timestamp (for local events)
    pub fn tick(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Update clock based on received timestamp (for received events)
    /// Returns the new local timestamp
    pub fn receive(&self, received_ts: u64) -> u64 {
        loop {
            let current = self.counter.load(Ordering::SeqCst);
            let new_val = current.max(received_ts) + 1;
            if self
                .counter
                .compare_exchange(current, new_val, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return new_val;
            }
        }
    }
}

impl Default for LamportClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for LamportClock {
    fn clone(&self) -> Self {
        Self {
            counter: AtomicU64::new(self.counter.load(Ordering::SeqCst)),
        }
    }
}

/// Vector clock for tracking causal relationships across nodes
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct VectorClock {
    /// Node ID -> logical timestamp
    pub clocks: BTreeMap<String, u64>,
}

impl VectorClock {
    pub fn new() -> Self {
        Self {
            clocks: BTreeMap::new(),
        }
    }

    /// Increment clock for a node
    pub fn increment(&mut self, node_id: &str) {
        let entry = self.clocks.entry(node_id.to_string()).or_insert(0);
        *entry += 1;
    }

    /// Get timestamp for a node
    pub fn get(&self, node_id: &str) -> u64 {
        self.clocks.get(node_id).copied().unwrap_or(0)
    }

    /// Merge with another vector clock (take max of each component)
    pub fn merge(&mut self, other: &VectorClock) {
        for (node, &ts) in &other.clocks {
            let entry = self.clocks.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(ts);
        }
    }

    /// Check if self happened-before other (self < other)
    pub fn happened_before(&self, other: &VectorClock) -> bool {
        let mut dominated = false;
        for (node, &ts) in &self.clocks {
            let other_ts = other.get(node);
            if ts > other_ts {
                return false;
            }
            if ts < other_ts {
                dominated = true;
            }
        }
        // Check nodes in other but not in self
        for (node, &ts) in &other.clocks {
            if !self.clocks.contains_key(node) && ts > 0 {
                dominated = true;
            }
        }
        dominated
    }

    /// Check if two clocks are concurrent (neither happened-before the other)
    pub fn concurrent(&self, other: &VectorClock) -> bool {
        !self.happened_before(other) && !other.happened_before(self) && self != other
    }

    /// Convert to BTreeMap for serialization in TraceEvent
    pub fn to_map(&self) -> BTreeMap<String, u64> {
        self.clocks.clone()
    }

    /// Create from BTreeMap
    pub fn from_map(map: BTreeMap<String, u64>) -> Self {
        Self { clocks: map }
    }
}

/// Causal context for a tracer node
#[derive(Debug)]
pub struct CausalTracer {
    /// Node ID for this tracer
    pub node_id: String,
    /// Lamport clock for simple ordering
    pub lamport: LamportClock,
    /// Vector clock for distributed ordering
    pub vclock: std::sync::RwLock<VectorClock>,
    /// Last event trace_id (for causal parent tracking)
    last_trace_id: std::sync::RwLock<Option<String>>,
}

impl CausalTracer {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            lamport: LamportClock::new(),
            vclock: std::sync::RwLock::new(VectorClock::new()),
            last_trace_id: std::sync::RwLock::new(None),
        }
    }

    /// Record a local event and get causal metadata
    pub fn record_event(&self) -> CausalMetadata {
        let lamport_ts = self.lamport.tick();

        let vclock = {
            let mut vc = self.vclock.write().unwrap();
            vc.increment(&self.node_id);
            vc.to_map()
        };

        let causal_parent = self.last_trace_id.read().unwrap().clone();

        CausalMetadata {
            lamport_ts,
            vclock,
            causal_parent,
        }
    }

    /// Update last trace_id after emitting an event
    pub fn set_last_trace_id(&self, trace_id: String) {
        let mut last = self.last_trace_id.write().unwrap();
        *last = Some(trace_id);
    }

    /// Receive an event from another node and update clocks
    pub fn receive_event(&self, lamport_ts: u64, vclock: &BTreeMap<String, u64>) {
        self.lamport.receive(lamport_ts);

        let other_vc = VectorClock::from_map(vclock.clone());
        let mut vc = self.vclock.write().unwrap();
        vc.merge(&other_vc);
    }

    /// Get current Lamport timestamp
    pub fn current_lamport(&self) -> u64 {
        self.lamport.current()
    }

    /// Get current vector clock
    pub fn current_vclock(&self) -> BTreeMap<String, u64> {
        self.vclock.read().unwrap().to_map()
    }
}

/// Causal metadata to attach to events
#[derive(Debug, Clone)]
pub struct CausalMetadata {
    pub lamport_ts: u64,
    pub vclock: BTreeMap<String, u64>,
    pub causal_parent: Option<String>,
}

/// Ordering result between two events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalOrder {
    /// First event happened before second
    Before,
    /// First event happened after second
    After,
    /// Events are concurrent (no causal relationship)
    Concurrent,
    /// Events are identical
    Equal,
}

/// Compare two events for causal ordering
pub fn compare_events(vc1: &BTreeMap<String, u64>, vc2: &BTreeMap<String, u64>) -> CausalOrder {
    let v1 = VectorClock::from_map(vc1.clone());
    let v2 = VectorClock::from_map(vc2.clone());

    if v1 == v2 {
        CausalOrder::Equal
    } else if v1.happened_before(&v2) {
        CausalOrder::Before
    } else if v2.happened_before(&v1) {
        CausalOrder::After
    } else {
        CausalOrder::Concurrent
    }
}

/// Sort events by causal order (topological sort)
/// Returns events in happened-before order, with concurrent events
/// ordered by Lamport timestamp as tiebreaker
pub fn sort_events_causally<T, F, G>(events: &mut [T], get_vclock: F, get_lamport: G)
where
    F: Fn(&T) -> Option<&BTreeMap<String, u64>>,
    G: Fn(&T) -> Option<u64>,
{
    events.sort_by(|a, b| {
        let vc_a = get_vclock(a);
        let vc_b = get_vclock(b);

        match (vc_a, vc_b) {
            (Some(va), Some(vb)) => {
                match compare_events(va, vb) {
                    CausalOrder::Before => std::cmp::Ordering::Less,
                    CausalOrder::After => std::cmp::Ordering::Greater,
                    CausalOrder::Equal => std::cmp::Ordering::Equal,
                    CausalOrder::Concurrent => {
                        // Use Lamport timestamp as tiebreaker
                        let la = get_lamport(a).unwrap_or(0);
                        let lb = get_lamport(b).unwrap_or(0);
                        la.cmp(&lb)
                    }
                }
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => {
                // Fall back to Lamport timestamp
                let la = get_lamport(a).unwrap_or(0);
                let lb = get_lamport(b).unwrap_or(0);
                la.cmp(&lb)
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lamport_clock() {
        let clock = LamportClock::new();
        assert_eq!(clock.current(), 0);

        let t1 = clock.tick();
        assert_eq!(t1, 1);

        let t2 = clock.tick();
        assert_eq!(t2, 2);

        // Receive a higher timestamp
        let t3 = clock.receive(10);
        assert_eq!(t3, 11);

        // Receive a lower timestamp
        let t4 = clock.receive(5);
        assert_eq!(t4, 12);
    }

    #[test]
    fn test_vector_clock_ordering() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();

        vc1.increment("node1");
        vc1.increment("node1");

        vc2.increment("node1");
        vc2.increment("node2");

        // vc1 did not happen before vc2 (concurrent)
        assert!(vc1.concurrent(&vc2));

        // Create a clear happened-before relationship
        let mut vc3 = VectorClock::new();
        vc3.increment("node1");

        let mut vc4 = vc3.clone();
        vc4.increment("node1");

        assert!(vc3.happened_before(&vc4));
        assert!(!vc4.happened_before(&vc3));
    }

    #[test]
    fn test_causal_tracer() {
        let tracer = CausalTracer::new("node1".to_string());

        let meta1 = tracer.record_event();
        assert_eq!(meta1.lamport_ts, 1);
        assert_eq!(meta1.vclock.get("node1"), Some(&1));
        assert!(meta1.causal_parent.is_none());

        tracer.set_last_trace_id("trace-001".to_string());

        let meta2 = tracer.record_event();
        assert_eq!(meta2.lamport_ts, 2);
        assert_eq!(meta2.vclock.get("node1"), Some(&2));
        assert_eq!(meta2.causal_parent, Some("trace-001".to_string()));
    }

    #[test]
    fn test_causal_tracer_receive() {
        let tracer = CausalTracer::new("node1".to_string());

        // Local event
        let _meta1 = tracer.record_event();

        // Receive event from node2 with higher Lamport timestamp
        let mut remote_vc = BTreeMap::new();
        remote_vc.insert("node2".to_string(), 5);
        tracer.receive_event(10, &remote_vc);

        // Next local event should have higher timestamps
        let meta2 = tracer.record_event();
        assert!(meta2.lamport_ts > 10);
        assert_eq!(meta2.vclock.get("node1"), Some(&2));
        assert_eq!(meta2.vclock.get("node2"), Some(&5));
    }

    #[test]
    fn test_compare_events() {
        let mut vc1 = BTreeMap::new();
        vc1.insert("node1".to_string(), 1);

        let mut vc2 = BTreeMap::new();
        vc2.insert("node1".to_string(), 2);

        assert_eq!(compare_events(&vc1, &vc2), CausalOrder::Before);
        assert_eq!(compare_events(&vc2, &vc1), CausalOrder::After);
        assert_eq!(compare_events(&vc1, &vc1), CausalOrder::Equal);

        let mut vc3 = BTreeMap::new();
        vc3.insert("node2".to_string(), 1);

        assert_eq!(compare_events(&vc1, &vc3), CausalOrder::Concurrent);
    }

    #[test]
    fn test_sort_events_causally() {
        #[derive(Debug, Clone)]
        struct TestEvent {
            id: &'static str,
            lamport: u64,
            vclock: BTreeMap<String, u64>,
        }

        let mut events = vec![
            TestEvent {
                id: "c",
                lamport: 3,
                vclock: {
                    let mut m = BTreeMap::new();
                    m.insert("n1".to_string(), 3);
                    m
                },
            },
            TestEvent {
                id: "a",
                lamport: 1,
                vclock: {
                    let mut m = BTreeMap::new();
                    m.insert("n1".to_string(), 1);
                    m
                },
            },
            TestEvent {
                id: "b",
                lamport: 2,
                vclock: {
                    let mut m = BTreeMap::new();
                    m.insert("n1".to_string(), 2);
                    m
                },
            },
        ];

        sort_events_causally(&mut events, |e| Some(&e.vclock), |e| Some(e.lamport));

        assert_eq!(events[0].id, "a");
        assert_eq!(events[1].id, "b");
        assert_eq!(events[2].id, "c");
    }
}
