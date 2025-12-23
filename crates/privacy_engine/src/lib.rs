use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionRule {
    pub pattern: String,
    pub replacement: String,
}

#[derive(Debug, Clone)]
pub struct PrivacyEngine {
    namespace_salt: String,
    secret_patterns: Vec<Regex>,
}

impl PrivacyEngine {
    pub fn new(namespace_id: &str) -> Self {
        // Deterministic salt per namespace
        let mut hasher = Sha256::new();
        hasher.update(b"ritma_privacy_v1:");
        hasher.update(namespace_id.as_bytes());
        let namespace_salt = hex::encode(hasher.finalize());

        // Common secret patterns
        let secret_patterns = vec![
            Regex::new(
                r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|bearer)\s*(?:[:=]|is)\s*[^\s]+",
            )
            .unwrap(),
            Regex::new(r"(?i)authorization:\s*bearer\s+[a-zA-Z0-9\-._~+/]+=*").unwrap(),
            Regex::new(r"[a-zA-Z0-9]{32,}").unwrap(), // high-entropy strings
            Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(), // emails
        ];

        Self {
            namespace_salt,
            secret_patterns,
        }
    }

    /// Deterministic hash with namespace salt
    pub fn hash_with_salt(&self, plaintext: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.namespace_salt);
        hasher.update(plaintext.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Detect secrets in text
    pub fn detect_secrets(&self, text: &str) -> Vec<String> {
        let mut secrets = Vec::new();
        for pattern in &self.secret_patterns {
            for mat in pattern.find_iter(text) {
                secrets.push(mat.as_str().to_string());
            }
        }
        secrets
    }

    /// Redact secrets from text
    pub fn redact_secrets(&self, text: &str) -> (String, Vec<RedactionRule>) {
        let mut redacted = text.to_string();
        let mut rules = Vec::new();

        for secret in self.detect_secrets(text) {
            let hash = self.hash_with_salt(&secret);
            let replacement = format!("[REDACTED:{}]", &hash[..16]);
            redacted = redacted.replace(&secret, &replacement);
            rules.push(RedactionRule {
                pattern: secret.clone(),
                replacement: replacement.clone(),
            });
        }

        (redacted, rules)
    }

    /// Hash IP addresses deterministically
    pub fn hash_ip(&self, ip: &str) -> String {
        self.hash_with_salt(ip)
    }

    /// Hash file paths deterministically
    pub fn hash_path(&self, path: &str) -> String {
        self.hash_with_salt(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_hashing() {
        let engine = PrivacyEngine::new("ns://test");
        let h1 = engine.hash_with_salt("secret123");
        let h2 = engine.hash_with_salt("secret123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_secret_detection() {
        let engine = PrivacyEngine::new("ns://test");
        let text = "password=mypass123 and token=abc123def456";
        let secrets = engine.detect_secrets(text);
        assert!(!secrets.is_empty());
    }

    #[test]
    fn test_redaction() {
        let engine = PrivacyEngine::new("ns://test");
        let text = "My password is secret123";
        let (redacted, rules) = engine.redact_secrets(text);
        assert!(redacted.contains("[REDACTED:"));
        assert!(!rules.is_empty());
    }
}
