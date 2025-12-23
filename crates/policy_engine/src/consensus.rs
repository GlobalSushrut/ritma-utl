// Consensus mechanism for policy decisions
// Implements multi-validator consensus with proof aggregation,
// weighted voting, and quorum tracking.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Trait for signature verification of consensus votes.
/// Implement this to verify validator signatures.
pub trait SignatureVerifier {
    /// Verify a vote's signature.
    ///
    /// * `vote` - The vote to verify.
    /// * `validator_public_key` - Optional public key for the validator.
    ///
    /// Returns true if signature is valid, false otherwise.
    fn verify_vote(&self, vote: &ConsensusVote, validator_public_key: Option<&str>) -> bool;
}

/// No-op signature verifier (accepts all signatures).
pub struct NoOpVerifier;

impl SignatureVerifier for NoOpVerifier {
    fn verify_vote(&self, _vote: &ConsensusVote, _validator_public_key: Option<&str>) -> bool {
        true
    }
}

/// Structured consensus decision kind used internally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusDecision {
    Allow,
    Deny,
    Other(String),
}

impl ConsensusDecision {
    pub fn as_str(&self) -> String {
        match self {
            ConsensusDecision::Allow => "allow".to_string(),
            ConsensusDecision::Deny => "deny".to_string(),
            ConsensusDecision::Other(s) => s.clone(),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "allow" => ConsensusDecision::Allow,
            "deny" => ConsensusDecision::Deny,
            other => ConsensusDecision::Other(other.to_string()),
        }
    }
}

impl std::str::FromStr for ConsensusDecision {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ConsensusDecision::parse(s))
    }
}

/// Consensus vote from a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVote {
    /// Unique validator identifier (e.g., DID)
    pub validator_id: String,
    /// Decision string ("allow", "deny", or custom)
    pub decision: String,
    /// Unix timestamp (seconds)
    pub timestamp: u64,
    /// Optional proof associated with this vote
    pub proof: Option<String>,
    /// Validator signature over the vote payload (not verified here)
    pub signature: String,
    /// Optional domain / scope (tenant, policy, etc.)
    #[serde(default)]
    pub domain: Option<String>,
}

/// Consensus result aggregating multiple votes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    /// Final decision string (for backward compatibility)
    pub decision: String,
    /// Structured decision kind
    pub decision_kind: ConsensusDecision,
    /// All votes that participated in this consensus
    pub votes: Vec<ConsensusVote>,
    /// Whether configured threshold was met for the chosen decision
    pub threshold_met: bool,
    /// Whether quorum of validators participated
    pub quorum_reached: bool,
    /// Total weight in favor of the chosen decision
    pub total_weight: u64,
    /// Configured weight threshold (if any)
    pub weight_threshold: Option<u64>,
    /// Hash over all votes for tamper detection
    pub consensus_hash: String,
    /// Aggregated proof over all vote proofs (if any)
    pub proof_aggregate: Option<String>,
}

/// Consensus engine configuration for policy decisions
pub struct ConsensusEngine {
    /// Minimum number of votes for the winning decision
    threshold: u32,
    /// Minimum number of distinct validators that must participate
    min_validators: u32,
    /// Optional total weight required for the winning decision
    weight_threshold: Option<u64>,
    /// Known validators and their weights
    validators: HashMap<String, u32>,
}

impl ConsensusEngine {
    /// Create a new consensus engine with equal-weight validators.
    ///
    /// * `threshold` - minimum number of votes for a decision.
    /// * `validators` - list of validator IDs (weight = 1 each).
    pub fn new(threshold: u32, validators: Vec<String>) -> Self {
        let mut map = HashMap::new();
        for v in validators {
            map.insert(v, 1);
        }
        Self {
            threshold,
            // By default, require at least `threshold` validators as quorum.
            min_validators: threshold,
            weight_threshold: None,
            validators: map,
        }
    }

    /// Create a consensus engine with explicit weights and thresholds.
    pub fn with_weights(
        threshold: u32,
        min_validators: u32,
        weight_threshold: Option<u64>,
        validators: HashMap<String, u32>,
    ) -> Self {
        Self {
            threshold,
            min_validators,
            weight_threshold,
            validators,
        }
    }

    /// Create a consensus engine from a TruthScript PolicyHeader.
    ///
    /// * `header` - PolicyHeader containing consensus configuration.
    /// * `validator_weights` - Map of validator IDs to their weights.
    ///
    /// Uses header.consensus_threshold if present, otherwise defaults to 2.
    /// Quorum is set to threshold or half of validators, whichever is smaller.
    pub fn from_policy_header(
        header: &truthscript::PolicyHeader,
        validator_weights: HashMap<String, u32>,
    ) -> Self {
        let threshold = header.consensus_threshold.unwrap_or(2);
        let validator_count = validator_weights.len() as u32;
        let min_validators = threshold.min(validator_count / 2 + 1);

        Self {
            threshold,
            min_validators,
            weight_threshold: None, // Could be extended via CUE
            validators: validator_weights,
        }
    }

    /// Evaluate consensus from collected votes with domain filtering and staleness check.
    ///
    /// * `votes` - All collected votes.
    /// * `expected_domain` - Only count votes matching this domain (None = accept all).
    /// * `max_age_secs` - Maximum age of votes in seconds (None = no staleness check).
    pub fn evaluate_with_domain(
        &self,
        votes: &[ConsensusVote],
        expected_domain: Option<&str>,
        max_age_secs: Option<u64>,
    ) -> ConsensusResult {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Filter votes by domain and staleness
        let valid_votes: Vec<&ConsensusVote> = votes
            .iter()
            .filter(|v| {
                // Domain check
                let domain_ok = match expected_domain {
                    Some(d) => v.domain.as_deref() == Some(d),
                    None => true,
                };

                // Staleness check
                let fresh = match max_age_secs {
                    Some(max_age) => now.saturating_sub(v.timestamp) <= max_age,
                    None => true,
                };

                domain_ok && fresh
            })
            .collect();

        self.evaluate_internal(&valid_votes)
    }

    /// Evaluate consensus from collected votes (no filtering).
    pub fn evaluate(&self, votes: &[ConsensusVote]) -> ConsensusResult {
        let vote_refs: Vec<&ConsensusVote> = votes.iter().collect();
        self.evaluate_internal(&vote_refs)
    }

    /// Evaluate consensus with signature verification.
    ///
    /// * `votes` - All collected votes.
    /// * `verifier` - Signature verifier implementation.
    /// * `validator_keys` - Map of validator IDs to their public keys.
    pub fn evaluate_with_verification<V: SignatureVerifier>(
        &self,
        votes: &[ConsensusVote],
        verifier: &V,
        validator_keys: &HashMap<String, String>,
    ) -> ConsensusResult {
        // Filter votes by signature validity
        let valid_votes: Vec<&ConsensusVote> = votes
            .iter()
            .filter(|v| {
                let key = validator_keys.get(&v.validator_id).map(|s| s.as_str());
                verifier.verify_vote(v, key)
            })
            .collect();

        self.evaluate_internal(&valid_votes)
    }

    /// Internal evaluation logic.
    fn evaluate_internal(&self, votes: &[&ConsensusVote]) -> ConsensusResult {
        // Count votes and weights by decision, only from known validators.
        let mut decision_counts: HashMap<String, u32> = HashMap::new();
        let mut decision_weights: HashMap<String, u64> = HashMap::new();
        let mut participating_validators: HashSet<String> = HashSet::new();

        for vote in votes {
            if let Some(weight) = self.validators.get(&vote.validator_id) {
                let w = *weight as u64;
                *decision_counts.entry(vote.decision.clone()).or_insert(0) += 1;
                *decision_weights.entry(vote.decision.clone()).or_insert(0) += w;
                participating_validators.insert(vote.validator_id.clone());
            }
        }

        // Convert back to owned votes for result
        let owned_votes: Vec<ConsensusVote> = votes.iter().map(|v| (*v).clone()).collect();

        // Find decision with the highest weight, breaking ties by count.
        let (decision, count, total_weight_for_decision) = decision_counts
            .iter()
            .map(|(d, c)| {
                let w = *decision_weights.get(d).unwrap_or(&0);
                (d.clone(), *c, w)
            })
            .max_by(|a, b| a.2.cmp(&b.2).then(a.1.cmp(&b.1)))
            .unwrap_or_else(|| ("deny".to_string(), 0, 0));

        let validator_count = participating_validators.len() as u32;

        let threshold_met = count >= self.threshold
            && validator_count >= self.min_validators
            && self
                .weight_threshold
                .map(|wt| total_weight_for_decision >= wt)
                .unwrap_or(true);

        let quorum_reached = validator_count >= self.min_validators;

        let decision_kind = ConsensusDecision::parse(&decision);

        ConsensusResult {
            decision: if threshold_met {
                decision.clone()
            } else {
                "deny".to_string()
            },
            decision_kind: if threshold_met {
                decision_kind
            } else {
                ConsensusDecision::Deny
            },
            votes: owned_votes.clone(),
            threshold_met,
            quorum_reached,
            total_weight: total_weight_for_decision,
            weight_threshold: self.weight_threshold,
            consensus_hash: self.compute_consensus_hash(&owned_votes),
            proof_aggregate: self.aggregate_proofs(&owned_votes),
        }
    }

    /// Compute hash of all votes for tamper detection
    fn compute_consensus_hash(&self, votes: &[ConsensusVote]) -> String {
        let mut hasher = Sha256::new();

        for vote in votes {
            let vote_json = serde_json::to_string(vote).unwrap_or_default();
            hasher.update(vote_json.as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    /// Aggregate proofs from all votes
    fn aggregate_proofs(&self, votes: &[ConsensusVote]) -> Option<String> {
        let proofs: Vec<String> = votes.iter().filter_map(|v| v.proof.clone()).collect();

        if proofs.is_empty() {
            return None;
        }

        // Simple concatenation for now, could use Merkle tree or proof aggregation
        let mut hasher = Sha256::new();
        for proof in &proofs {
            hasher.update(proof.as_bytes());
        }

        Some(hex::encode(hasher.finalize()))
    }

    /// Verify a consensus result
    pub fn verify(&self, result: &ConsensusResult) -> bool {
        // Check threshold and quorum flags
        if !result.threshold_met || !result.quorum_reached {
            return false;
        }

        // Verify consensus hash
        let computed_hash = self.compute_consensus_hash(&result.votes);
        if computed_hash != result.consensus_hash {
            return false;
        }

        // Verify all votes are from known validators and recompute weight
        let mut total_weight = 0u64;
        let mut validators_seen: HashSet<String> = HashSet::new();
        for vote in &result.votes {
            if let Some(w) = self.validators.get(&vote.validator_id) {
                total_weight += *w as u64;
                validators_seen.insert(vote.validator_id.clone());
            } else {
                return false;
            }
        }

        if let Some(wt) = self.weight_threshold {
            if total_weight < wt {
                return false;
            }
        }

        validators_seen.len() as u32 >= self.min_validators
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_requires_threshold() {
        let engine = ConsensusEngine::new(
            2,
            vec!["v1".to_string(), "v2".to_string(), "v3".to_string()],
        );

        let votes = vec![
            ConsensusVote {
                validator_id: "v1".to_string(),
                decision: "allow".to_string(),
                timestamp: 100,
                proof: None,
                signature: "sig1".to_string(),
                domain: None,
            },
            ConsensusVote {
                validator_id: "v2".to_string(),
                decision: "deny".to_string(),
                timestamp: 101,
                proof: None,
                signature: "sig2".to_string(),
                domain: None,
            },
        ];

        let result = engine.evaluate(&votes);
        assert!(!result.threshold_met); // Only 1 vote per decision, threshold is 2
    }

    #[test]
    fn consensus_met_with_majority() {
        let engine = ConsensusEngine::new(
            2,
            vec!["v1".to_string(), "v2".to_string(), "v3".to_string()],
        );

        let votes = vec![
            ConsensusVote {
                validator_id: "v1".to_string(),
                decision: "allow".to_string(),
                timestamp: 100,
                proof: None,
                signature: "sig1".to_string(),
                domain: None,
            },
            ConsensusVote {
                validator_id: "v2".to_string(),
                decision: "allow".to_string(),
                timestamp: 101,
                proof: None,
                signature: "sig2".to_string(),
                domain: None,
            },
        ];

        let result = engine.evaluate(&votes);
        assert!(result.threshold_met);
        assert_eq!(result.decision, "allow");
    }

    #[test]
    fn domain_filtering_excludes_wrong_domain() {
        let engine = ConsensusEngine::new(
            2,
            vec!["v1".to_string(), "v2".to_string(), "v3".to_string()],
        );

        let votes = vec![
            ConsensusVote {
                validator_id: "v1".to_string(),
                decision: "allow".to_string(),
                timestamp: 100,
                proof: None,
                signature: "sig1".to_string(),
                domain: Some("tenant_a".to_string()),
            },
            ConsensusVote {
                validator_id: "v2".to_string(),
                decision: "allow".to_string(),
                timestamp: 101,
                proof: None,
                signature: "sig2".to_string(),
                domain: Some("tenant_b".to_string()), // Wrong domain
            },
            ConsensusVote {
                validator_id: "v3".to_string(),
                decision: "allow".to_string(),
                timestamp: 102,
                proof: None,
                signature: "sig3".to_string(),
                domain: Some("tenant_a".to_string()),
            },
        ];

        let result = engine.evaluate_with_domain(&votes, Some("tenant_a"), None);
        assert!(result.threshold_met); // v1 and v3 both voted allow for tenant_a
        assert_eq!(result.decision, "allow");
        assert_eq!(result.votes.len(), 2); // Only 2 votes counted
    }

    #[test]
    fn staleness_check_excludes_old_votes() {
        let engine = ConsensusEngine::new(2, vec!["v1".to_string(), "v2".to_string()]);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let votes = vec![
            ConsensusVote {
                validator_id: "v1".to_string(),
                decision: "allow".to_string(),
                timestamp: now - 100, // Old vote
                proof: None,
                signature: "sig1".to_string(),
                domain: None,
            },
            ConsensusVote {
                validator_id: "v2".to_string(),
                decision: "allow".to_string(),
                timestamp: now - 5, // Fresh vote
                proof: None,
                signature: "sig2".to_string(),
                domain: None,
            },
        ];

        let result = engine.evaluate_with_domain(&votes, None, Some(30)); // 30 second window
        assert!(!result.threshold_met); // Only 1 fresh vote, threshold is 2
        assert_eq!(result.votes.len(), 1);
    }
}
