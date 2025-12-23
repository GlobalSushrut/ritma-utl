use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AptTrackerError {
    #[error("Failed to correlate windows: {0}")]
    CorrelationError(String),
    #[error("Failed to detect dormant backdoor: {0}")]
    DormantDetectionError(String),
    #[error("Failed to attribute campaign: {0}")]
    CampaignAttributionError(String),
}

pub type Result<T> = std::result::Result<T, AptTrackerError>;

/// APT campaign - a series of related attacks over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AptCampaign {
    pub campaign_id: String,
    pub first_seen: String,
    pub last_seen: String,
    pub attack_stages: Vec<AttackStage>,
    pub behavioral_fingerprint: BehavioralFingerprint,
    pub confidence_score: f64, // 0.0-1.0
    pub severity: Severity,
    pub attribution: Option<ThreatActorAttribution>,
}

/// Attack stage in the cyber kill chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    pub stage: KillChainStage,
    pub timestamp: String,
    pub window_id: String,
    pub techniques: Vec<String>, // MITRE ATT&CK techniques
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KillChainStage {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
}

/// Behavioral fingerprint for attribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    pub process_lineage_pattern: Vec<String>,
    pub network_pattern: NetworkPattern,
    pub timing_pattern: TimingPattern,
    pub syscall_signature: Vec<u64>,
    pub file_operation_pattern: Vec<String>,
    pub fingerprint_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPattern {
    pub c2_domains: Vec<String>,
    pub c2_ips: Vec<String>,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
    pub beaconing_interval_secs: Option<u64>,
    pub jitter_percent: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingPattern {
    pub active_hours: Vec<u8>, // Hours of day (0-23)
    pub active_days: Vec<u8>,  // Days of week (0-6)
    pub sleep_duration_secs: Option<u64>,
    pub burst_pattern: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorAttribution {
    pub actor_name: String,
    pub confidence: f64,
    pub known_ttps: Vec<String>, // Tactics, Techniques, Procedures
    pub similar_campaigns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Dormant backdoor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DormantBackdoor {
    pub backdoor_id: String,
    pub pid: i32,
    pub process_name: String,
    pub first_detected: String,
    pub last_activity: String,
    pub sleep_duration_secs: u64,
    pub wakeup_count: u32,
    pub persistence_mechanism: Vec<String>,
    pub c2_callback_pattern: Option<BeaconPattern>,
    pub severity: Severity,
}

/// C2 beacon pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconPattern {
    pub interval_secs: u64,
    pub jitter_secs: u64,
    pub destination: String,
    pub port: u16,
    pub protocol: String,
    pub packet_size: usize,
    pub detected_beacons: u32,
}

/// Cross-window correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub correlation_id: String,
    pub window_ids: Vec<String>,
    pub time_span_hours: f64,
    pub correlation_score: f64,
    pub shared_indicators: Vec<String>,
    pub attack_progression: Vec<KillChainStage>,
}

/// Cross-window correlation engine
pub struct CrossWindowCorrelator {
    /// Window data by ID
    windows: HashMap<String, WindowData>,

    /// Correlations found
    correlations: Vec<CorrelationResult>,

    /// Correlation threshold
    threshold: f64,
}

#[derive(Debug, Clone)]
pub struct WindowData {
    pub window_id: String,
    pub timestamp: i64,
    pub process_hashes: HashSet<String>,
    pub file_hashes: HashSet<String>,
    pub network_destinations: HashSet<String>,
    pub syscall_signature: Vec<u64>,
}

impl CrossWindowCorrelator {
    pub fn new(threshold: f64) -> Self {
        Self {
            windows: HashMap::new(),
            correlations: Vec::new(),
            threshold,
        }
    }

    /// Add a window for correlation
    pub fn add_window(&mut self, data: WindowData) {
        self.windows.insert(data.window_id.clone(), data);
    }

    /// Correlate windows to find related attacks
    pub fn correlate_windows(&mut self) -> Result<Vec<CorrelationResult>> {
        let mut new_correlations = Vec::new();
        let window_ids: Vec<String> = self.windows.keys().cloned().collect();

        // Compare all pairs of windows
        for i in 0..window_ids.len() {
            for j in (i + 1)..window_ids.len() {
                let w1 = &self.windows[&window_ids[i]];
                let w2 = &self.windows[&window_ids[j]];

                let score = self.compute_correlation_score(w1, w2);

                if score > self.threshold {
                    let shared = self.find_shared_indicators(w1, w2);

                    let correlation = CorrelationResult {
                        correlation_id: format!("corr_{}_{}", w1.window_id, w2.window_id),
                        window_ids: vec![w1.window_id.clone(), w2.window_id.clone()],
                        time_span_hours: ((w2.timestamp - w1.timestamp) as f64) / 3600.0,
                        correlation_score: score,
                        shared_indicators: shared,
                        attack_progression: vec![], // TODO: infer from data
                    };

                    log::info!(
                        "Correlation found: {} (score: {:.2})",
                        correlation.correlation_id,
                        score
                    );
                    new_correlations.push(correlation.clone());
                    self.correlations.push(correlation);
                }
            }
        }

        Ok(new_correlations)
    }

    /// Compute correlation score between two windows
    fn compute_correlation_score(&self, w1: &WindowData, w2: &WindowData) -> f64 {
        let mut score = 0.0;

        // Process hash overlap
        let process_overlap = w1.process_hashes.intersection(&w2.process_hashes).count();
        score += (process_overlap as f64) * 0.3;

        // File hash overlap
        let file_overlap = w1.file_hashes.intersection(&w2.file_hashes).count();
        score += (file_overlap as f64) * 0.2;

        // Network destination overlap
        let network_overlap = w1
            .network_destinations
            .intersection(&w2.network_destinations)
            .count();
        score += (network_overlap as f64) * 0.3;

        // Syscall signature similarity
        let syscall_similarity =
            self.compute_syscall_similarity(&w1.syscall_signature, &w2.syscall_signature);
        score += syscall_similarity * 0.2;

        score.min(1.0)
    }

    /// Compute syscall signature similarity
    fn compute_syscall_similarity(&self, sig1: &[u64], sig2: &[u64]) -> f64 {
        if sig1.is_empty() || sig2.is_empty() {
            return 0.0;
        }

        let set1: HashSet<_> = sig1.iter().collect();
        let set2: HashSet<_> = sig2.iter().collect();

        let intersection = set1.intersection(&set2).count();
        let union = set1.union(&set2).count();

        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// Find shared indicators between windows
    fn find_shared_indicators(&self, w1: &WindowData, w2: &WindowData) -> Vec<String> {
        let mut shared = Vec::new();

        for hash in w1.process_hashes.intersection(&w2.process_hashes) {
            shared.push(format!("process:{hash}"));
        }

        for hash in w1.file_hashes.intersection(&w2.file_hashes) {
            shared.push(format!("file:{hash}"));
        }

        for dest in w1
            .network_destinations
            .intersection(&w2.network_destinations)
        {
            shared.push(format!("network:{dest}"));
        }

        shared
    }

    /// Get all correlations
    pub fn get_correlations(&self) -> &[CorrelationResult] {
        &self.correlations
    }
}

/// Dormant backdoor detector
pub struct DormantBackdoorDetector {
    /// Tracked processes
    tracked_processes: HashMap<i32, ProcessTrackingInfo>,

    /// Detected backdoors
    backdoors: Vec<DormantBackdoor>,

    /// Sleep threshold (seconds)
    sleep_threshold_secs: u64,
}

#[derive(Debug, Clone)]
struct ProcessTrackingInfo {
    pid: i32,
    name: String,
    first_seen: i64,
    last_activity: i64,
    activity_count: u32,
    sleep_periods: Vec<(i64, i64)>, // (start, end)
}

impl DormantBackdoorDetector {
    pub fn new(sleep_threshold_secs: u64) -> Self {
        Self {
            tracked_processes: HashMap::new(),
            backdoors: Vec::new(),
            sleep_threshold_secs,
        }
    }

    /// Track process activity
    pub fn track_process_activity(&mut self, pid: i32, name: String, timestamp: i64) {
        let should_detect;
        let info_clone;

        {
            let info = self
                .tracked_processes
                .entry(pid)
                .or_insert_with(|| ProcessTrackingInfo {
                    pid,
                    name: name.clone(),
                    first_seen: timestamp,
                    last_activity: timestamp,
                    activity_count: 0,
                    sleep_periods: Vec::new(),
                });

            // Check for sleep period
            let sleep_duration = timestamp - info.last_activity;
            if sleep_duration > self.sleep_threshold_secs as i64 {
                info.sleep_periods.push((info.last_activity, timestamp));
            }

            should_detect = info.sleep_periods.len() >= 3;
            info_clone = info.clone();

            info.last_activity = timestamp;
            info.activity_count += 1;
        }

        // Detect dormant backdoor outside of borrow
        if should_detect {
            self.detect_dormant_backdoor(&info_clone);
        }
    }

    /// Detect dormant backdoor
    fn detect_dormant_backdoor(&mut self, info: &ProcessTrackingInfo) {
        let avg_sleep = if !info.sleep_periods.is_empty() {
            let total: i64 = info
                .sleep_periods
                .iter()
                .map(|(start, end)| end - start)
                .sum();
            (total / info.sleep_periods.len() as i64) as u64
        } else {
            0
        };

        let backdoor = DormantBackdoor {
            backdoor_id: format!("backdoor_{}", info.pid),
            pid: info.pid,
            process_name: info.name.clone(),
            first_detected: chrono::DateTime::from_timestamp(info.first_seen, 0)
                .unwrap_or(chrono::DateTime::from_timestamp(0, 0).unwrap())
                .to_rfc3339(),
            last_activity: chrono::DateTime::from_timestamp(info.last_activity, 0)
                .unwrap_or(chrono::DateTime::from_timestamp(0, 0).unwrap())
                .to_rfc3339(),
            sleep_duration_secs: avg_sleep,
            wakeup_count: info.sleep_periods.len() as u32,
            persistence_mechanism: vec![], // TODO: detect persistence
            c2_callback_pattern: None,     // TODO: detect beaconing
            severity: if avg_sleep > 3600 {
                Severity::High
            } else {
                Severity::Medium
            },
        };

        log::warn!(
            "Dormant backdoor detected: PID {} (avg sleep: {}s)",
            info.pid,
            avg_sleep
        );
        self.backdoors.push(backdoor);
    }

    /// Get detected backdoors
    pub fn get_backdoors(&self) -> &[DormantBackdoor] {
        &self.backdoors
    }
}

/// C2 beacon pattern recognizer
pub struct BeaconPatternRecognizer {
    /// Network connections by process
    connections: HashMap<i32, Vec<NetworkConnection>>,

    /// Detected beacon patterns
    beacons: Vec<BeaconPattern>,

    /// Minimum beacons to confirm pattern
    min_beacons: u32,
}

#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub timestamp: i64,
    pub destination: String,
    pub port: u16,
    pub protocol: String,
    pub bytes_sent: usize,
}

impl BeaconPatternRecognizer {
    pub fn new(min_beacons: u32) -> Self {
        Self {
            connections: HashMap::new(),
            beacons: Vec::new(),
            min_beacons,
        }
    }

    /// Record network connection
    pub fn record_connection(&mut self, pid: i32, conn: NetworkConnection) {
        self.connections.entry(pid).or_default().push(conn);
    }

    /// Analyze connections for beaconing patterns
    pub fn analyze_beaconing(&mut self, pid: i32) -> Option<BeaconPattern> {
        let conns = self.connections.get(&pid)?;

        if conns.len() < self.min_beacons as usize {
            return None;
        }

        // Group by destination
        let mut by_dest: HashMap<String, Vec<&NetworkConnection>> = HashMap::new();
        for conn in conns {
            by_dest
                .entry(conn.destination.clone())
                .or_default()
                .push(conn);
        }

        // Check each destination for regular intervals
        for (dest, dest_conns) in by_dest {
            if dest_conns.len() < self.min_beacons as usize {
                continue;
            }

            // Calculate intervals
            let mut intervals = Vec::new();
            for i in 1..dest_conns.len() {
                let interval = (dest_conns[i].timestamp - dest_conns[i - 1].timestamp) as u64;
                intervals.push(interval);
            }

            // Check for regular pattern
            if intervals.is_empty() {
                continue;
            }

            let avg_interval = intervals.iter().sum::<u64>() / intervals.len() as u64;
            let variance: f64 = intervals
                .iter()
                .map(|&i| {
                    let diff = i as f64 - avg_interval as f64;
                    diff * diff
                })
                .sum::<f64>()
                / intervals.len() as f64;
            let std_dev = variance.sqrt();
            let jitter = std_dev;

            // If jitter is low relative to interval, it's likely beaconing
            let jitter_percent = (jitter / avg_interval as f64) * 100.0;

            if jitter_percent < 30.0 {
                // Less than 30% jitter
                let pattern = BeaconPattern {
                    interval_secs: avg_interval,
                    jitter_secs: jitter as u64,
                    destination: dest.clone(),
                    port: dest_conns[0].port,
                    protocol: dest_conns[0].protocol.clone(),
                    packet_size: dest_conns.iter().map(|c| c.bytes_sent).sum::<usize>()
                        / dest_conns.len(),
                    detected_beacons: dest_conns.len() as u32,
                };

                log::warn!(
                    "C2 beaconing detected: {dest} every {avg_interval}s (jitter: {jitter_percent:.1}%)"
                );
                self.beacons.push(pattern.clone());
                return Some(pattern);
            }
        }

        None
    }

    /// Get all detected beacons
    pub fn get_beacons(&self) -> &[BeaconPattern] {
        &self.beacons
    }
}

/// Campaign attribution engine
pub struct CampaignAttributor {
    /// Known campaigns
    campaigns: HashMap<String, AptCampaign>,

    /// Behavioral fingerprints
    fingerprints: HashMap<String, BehavioralFingerprint>,
}

impl CampaignAttributor {
    pub fn new() -> Self {
        Self {
            campaigns: HashMap::new(),
            fingerprints: HashMap::new(),
        }
    }

    /// Create or update campaign
    pub fn attribute_to_campaign(
        &mut self,
        fingerprint: BehavioralFingerprint,
        stage: AttackStage,
    ) -> String {
        // Find matching campaign
        let mut matching_campaign_id = None;
        let mut best_similarity = 0.0;

        for (campaign_id, campaign) in &self.campaigns {
            let similarity =
                self.compute_fingerprint_similarity(&fingerprint, &campaign.behavioral_fingerprint);

            if similarity > 0.7 && similarity > best_similarity {
                matching_campaign_id = Some(campaign_id.clone());
                best_similarity = similarity;
            }
        }

        // Update matching campaign
        if let Some(campaign_id) = matching_campaign_id {
            if let Some(campaign) = self.campaigns.get_mut(&campaign_id) {
                campaign.attack_stages.push(stage.clone());
                campaign.last_seen = chrono::Utc::now().to_rfc3339();
                campaign.confidence_score = (campaign.confidence_score + best_similarity) / 2.0;
                return campaign_id;
            }
        }

        // Create new campaign
        let campaign_id = format!("campaign_{}", uuid::Uuid::new_v4());
        let campaign = AptCampaign {
            campaign_id: campaign_id.clone(),
            first_seen: chrono::Utc::now().to_rfc3339(),
            last_seen: chrono::Utc::now().to_rfc3339(),
            attack_stages: vec![stage],
            behavioral_fingerprint: fingerprint.clone(),
            confidence_score: 0.8,
            severity: Severity::High,
            attribution: None,
        };

        self.campaigns.insert(campaign_id.clone(), campaign);
        self.fingerprints.insert(campaign_id.clone(), fingerprint);

        log::info!("New APT campaign detected: {campaign_id}");
        campaign_id
    }

    /// Compute fingerprint similarity
    fn compute_fingerprint_similarity(
        &self,
        fp1: &BehavioralFingerprint,
        fp2: &BehavioralFingerprint,
    ) -> f64 {
        let mut score = 0.0;

        // Network pattern similarity
        let net1 = &fp1.network_pattern;
        let net2 = &fp2.network_pattern;

        let domain_overlap = net1
            .c2_domains
            .iter()
            .filter(|d| net2.c2_domains.contains(d))
            .count();
        score += (domain_overlap as f64 / net1.c2_domains.len().max(1) as f64) * 0.4;

        // Syscall signature similarity
        let sig1: HashSet<_> = fp1.syscall_signature.iter().collect();
        let sig2: HashSet<_> = fp2.syscall_signature.iter().collect();
        let sig_overlap = sig1.intersection(&sig2).count();
        let sig_union = sig1.union(&sig2).count();
        if sig_union > 0 {
            score += (sig_overlap as f64 / sig_union as f64) * 0.3;
        }

        // Timing pattern similarity
        if fp1.timing_pattern.active_hours == fp2.timing_pattern.active_hours {
            score += 0.3;
        }

        score.min(1.0)
    }

    /// Get campaign by ID
    pub fn get_campaign(&self, campaign_id: &str) -> Option<&AptCampaign> {
        self.campaigns.get(campaign_id)
    }

    /// Get all campaigns
    pub fn get_all_campaigns(&self) -> Vec<&AptCampaign> {
        self.campaigns.values().collect()
    }
}

impl Default for CampaignAttributor {
    fn default() -> Self {
        Self::new()
    }
}

/// Main APT tracker
pub struct AptTracker {
    correlator: CrossWindowCorrelator,
    backdoor_detector: DormantBackdoorDetector,
    beacon_recognizer: BeaconPatternRecognizer,
    campaign_attributor: CampaignAttributor,
}

impl AptTracker {
    pub fn new(correlation_threshold: f64, sleep_threshold_secs: u64, min_beacons: u32) -> Self {
        Self {
            correlator: CrossWindowCorrelator::new(correlation_threshold),
            backdoor_detector: DormantBackdoorDetector::new(sleep_threshold_secs),
            beacon_recognizer: BeaconPatternRecognizer::new(min_beacons),
            campaign_attributor: CampaignAttributor::new(),
        }
    }

    /// Add window for correlation
    pub fn add_window(&mut self, data: WindowData) {
        self.correlator.add_window(data);
    }

    /// Track process activity
    pub fn track_process(&mut self, pid: i32, name: String, timestamp: i64) {
        self.backdoor_detector
            .track_process_activity(pid, name, timestamp);
    }

    /// Record network connection
    pub fn record_connection(&mut self, pid: i32, conn: NetworkConnection) {
        self.beacon_recognizer.record_connection(pid, conn);
    }

    /// Run full analysis
    pub fn analyze(&mut self) -> Result<AptAnalysisResult> {
        let correlations = self.correlator.correlate_windows()?;
        let backdoors = self.backdoor_detector.get_backdoors().to_vec();
        let beacons = self.beacon_recognizer.get_beacons().to_vec();
        let campaigns = self
            .campaign_attributor
            .get_all_campaigns()
            .into_iter()
            .cloned()
            .collect();

        Ok(AptAnalysisResult {
            correlations,
            backdoors,
            beacons,
            campaigns,
        })
    }

    /// Get campaign attributor
    pub fn get_campaign_attributor(&mut self) -> &mut CampaignAttributor {
        &mut self.campaign_attributor
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AptAnalysisResult {
    pub correlations: Vec<CorrelationResult>,
    pub backdoors: Vec<DormantBackdoor>,
    pub beacons: Vec<BeaconPattern>,
    pub campaigns: Vec<AptCampaign>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_window_correlation() {
        let mut correlator = CrossWindowCorrelator::new(0.3); // Lower threshold

        let mut w1_processes = HashSet::new();
        w1_processes.insert("hash1".to_string());
        w1_processes.insert("hash2".to_string());

        let mut w1_network = HashSet::new();
        w1_network.insert("evil.com:443".to_string());

        let w1 = WindowData {
            window_id: "w1".to_string(),
            timestamp: 1000,
            process_hashes: w1_processes.clone(),
            file_hashes: HashSet::new(),
            network_destinations: w1_network.clone(),
            syscall_signature: vec![1, 2, 3],
        };

        let w2 = WindowData {
            window_id: "w2".to_string(),
            timestamp: 2000,
            process_hashes: w1_processes,
            file_hashes: HashSet::new(),
            network_destinations: w1_network,
            syscall_signature: vec![1, 2, 3],
        };

        correlator.add_window(w1);
        correlator.add_window(w2);

        let results = correlator.correlate_windows().unwrap();
        assert!(!results.is_empty());
        assert!(results[0].correlation_score > 0.3);
    }

    #[test]
    fn test_dormant_backdoor_detection() {
        let mut detector = DormantBackdoorDetector::new(3600);

        // Simulate process with long sleep periods
        detector.track_process_activity(1000, "backdoor".to_string(), 1000);
        detector.track_process_activity(1000, "backdoor".to_string(), 5000); // 4000s sleep
        detector.track_process_activity(1000, "backdoor".to_string(), 9000); // 4000s sleep
        detector.track_process_activity(1000, "backdoor".to_string(), 13000); // 4000s sleep

        assert!(!detector.get_backdoors().is_empty());
    }

    #[test]
    fn test_beacon_pattern_recognition() {
        let mut recognizer = BeaconPatternRecognizer::new(3);

        // Simulate regular beaconing
        for i in 0..5 {
            recognizer.record_connection(
                1000,
                NetworkConnection {
                    timestamp: 1000 + (i * 60), // Every 60 seconds
                    destination: "evil.com".to_string(),
                    port: 443,
                    protocol: "https".to_string(),
                    bytes_sent: 100,
                },
            );
        }

        let pattern = recognizer.analyze_beaconing(1000);
        assert!(pattern.is_some());
    }
}
