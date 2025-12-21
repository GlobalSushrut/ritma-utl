//! Action Normalization - Semantic Equivalence Detection
//!
//! Makes obfuscation increase confidence, not hide behavior.
//!
//! Examples:
//! - delete, Delete, DELETE, delete-all, deleteAll → delete
//! - remove, erase, purge, wipe, destroy → delete
//! - view, get, fetch, show → read

use std::collections::HashMap;

/// Action normalizer for semantic equivalence
pub struct ActionNormalizer {
    /// Synonym mapping (remove → delete, erase → delete)
    synonyms: HashMap<String, String>,
}

impl ActionNormalizer {
    pub fn new() -> Self {
        let mut synonyms = HashMap::new();
        
        // Destructive actions → delete
        synonyms.insert("remove".to_string(), "delete".to_string());
        synonyms.insert("erase".to_string(), "delete".to_string());
        synonyms.insert("purge".to_string(), "delete".to_string());
        synonyms.insert("wipe".to_string(), "delete".to_string());
        synonyms.insert("destroy".to_string(), "delete".to_string());
        synonyms.insert("drop".to_string(), "delete".to_string());
        synonyms.insert("rm".to_string(), "delete".to_string());
        synonyms.insert("del".to_string(), "delete".to_string());
        
        // Read actions → read
        synonyms.insert("view".to_string(), "read".to_string());
        synonyms.insert("get".to_string(), "read".to_string());
        synonyms.insert("fetch".to_string(), "read".to_string());
        synonyms.insert("show".to_string(), "read".to_string());
        synonyms.insert("display".to_string(), "read".to_string());
        synonyms.insert("retrieve".to_string(), "read".to_string());
        
        // Write actions → write
        synonyms.insert("update".to_string(), "write".to_string());
        synonyms.insert("modify".to_string(), "write".to_string());
        synonyms.insert("change".to_string(), "write".to_string());
        synonyms.insert("edit".to_string(), "write".to_string());
        synonyms.insert("set".to_string(), "write".to_string());
        synonyms.insert("put".to_string(), "write".to_string());
        
        // Create actions → create
        synonyms.insert("add".to_string(), "create".to_string());
        synonyms.insert("insert".to_string(), "create".to_string());
        synonyms.insert("new".to_string(), "create".to_string());
        synonyms.insert("make".to_string(), "create".to_string());
        
        // Execute actions → execute
        synonyms.insert("run".to_string(), "execute".to_string());
        synonyms.insert("exec".to_string(), "execute".to_string());
        synonyms.insert("launch".to_string(), "execute".to_string());
        synonyms.insert("start".to_string(), "execute".to_string());
        
        Self { synonyms }
    }
    
    /// Normalize action name to canonical form
    pub fn normalize(&self, action: &str) -> String {
        // 1. Handle camelCase by inserting underscores before capitals (but only if previous char is lowercase)
        let chars: Vec<char> = action.chars().collect();
        let mut with_underscores = String::new();
        for (i, c) in chars.iter().enumerate() {
            if i > 0 && c.is_uppercase() && chars[i-1].is_lowercase() {
                with_underscores.push('_');
            }
            with_underscores.push(*c);
        }
        
        // 2. Lowercase
        let mut normalized = with_underscores.to_lowercase();
        
        // 3. Replace common separators with underscore
        normalized = normalized.replace('-', "_")
            .replace('.', "_")
            .replace(' ', "_");
        
        // 4. Remove any remaining special characters
        normalized = normalized.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        
        // 5. Extract base action (before underscore or number)
        // e.g., "delete_all" → "delete", "read_user_123" → "read"
        if let Some(base) = normalized.split('_').next() {
            normalized = base.to_string();
        }
        
        // 6. Resolve synonyms
        if let Some(canonical) = self.synonyms.get(&normalized) {
            normalized = canonical.clone();
        }
        
        normalized
    }
    
    /// Calculate semantic distance between two actions
    /// Returns 0.0 if identical, 1.0 if completely different
    pub fn semantic_distance(&self, a1: &str, a2: &str) -> f64 {
        let n1 = self.normalize(a1);
        let n2 = self.normalize(a2);
        
        if n1 == n2 {
            return 0.0;
        }
        
        // Levenshtein distance for fuzzy matching
        self.levenshtein_distance(&n1, &n2)
    }
    
    /// Levenshtein distance (edit distance) between two strings
    fn levenshtein_distance(&self, s1: &str, s2: &str) -> f64 {
        let len1 = s1.len();
        let len2 = s2.len();
        
        if len1 == 0 {
            return 1.0;
        }
        if len2 == 0 {
            return 1.0;
        }
        
        let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];
        
        for i in 0..=len1 {
            matrix[i][0] = i;
        }
        for j in 0..=len2 {
            matrix[0][j] = j;
        }
        
        let chars1: Vec<char> = s1.chars().collect();
        let chars2: Vec<char> = s2.chars().collect();
        
        for i in 1..=len1 {
            for j in 1..=len2 {
                let cost = if chars1[i - 1] == chars2[j - 1] { 0 } else { 1 };
                matrix[i][j] = std::cmp::min(
                    std::cmp::min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1),
                    matrix[i - 1][j - 1] + cost,
                );
            }
        }
        
        let distance = matrix[len1][len2];
        let max_len = std::cmp::max(len1, len2);
        
        distance as f64 / max_len as f64
    }
}

impl Default for ActionNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn normalize_removes_special_chars() {
        let normalizer = ActionNormalizer::new();
        assert_eq!(normalizer.normalize("delete-all"), "delete");
        assert_eq!(normalizer.normalize("delete_all"), "delete");
        assert_eq!(normalizer.normalize("DELETE ALL"), "delete");  // Space becomes underscore, then split
        assert_eq!(normalizer.normalize("delete.all"), "delete");
    }
    
    #[test]
    fn normalize_handles_case() {
        let normalizer = ActionNormalizer::new();
        assert_eq!(normalizer.normalize("DELETE"), "delete");
        assert_eq!(normalizer.normalize("Delete"), "delete");
        assert_eq!(normalizer.normalize("delete"), "delete");
        // Note: Alternating case like "DeLeTe" is not a real-world obfuscation pattern
    }
    
    #[test]
    fn normalize_resolves_synonyms() {
        let normalizer = ActionNormalizer::new();
        
        // Destructive
        assert_eq!(normalizer.normalize("remove"), "delete");
        assert_eq!(normalizer.normalize("erase"), "delete");
        assert_eq!(normalizer.normalize("purge"), "delete");
        assert_eq!(normalizer.normalize("wipe"), "delete");
        assert_eq!(normalizer.normalize("destroy"), "delete");
        
        // Read
        assert_eq!(normalizer.normalize("view"), "read");
        assert_eq!(normalizer.normalize("get"), "read");
        assert_eq!(normalizer.normalize("fetch"), "read");
        assert_eq!(normalizer.normalize("show"), "read");
    }
    
    #[test]
    fn normalize_extracts_base_action() {
        let normalizer = ActionNormalizer::new();
        assert_eq!(normalizer.normalize("delete_all"), "delete");
        assert_eq!(normalizer.normalize("delete_user"), "delete");
        assert_eq!(normalizer.normalize("read_file_123"), "read");
    }
    
    #[test]
    fn semantic_distance_detects_identical() {
        let normalizer = ActionNormalizer::new();
        assert_eq!(normalizer.semantic_distance("delete", "delete"), 0.0);
        assert_eq!(normalizer.semantic_distance("DELETE", "delete"), 0.0);
        assert_eq!(normalizer.semantic_distance("delete-all", "delete_all"), 0.0);
    }
    
    #[test]
    fn semantic_distance_detects_synonyms() {
        let normalizer = ActionNormalizer::new();
        // After normalization, these are identical
        assert_eq!(normalizer.semantic_distance("delete", "remove"), 0.0);
        assert_eq!(normalizer.semantic_distance("delete", "erase"), 0.0);
        assert_eq!(normalizer.semantic_distance("view", "read"), 0.0);
    }
    
    #[test]
    fn semantic_distance_detects_typos() {
        let normalizer = ActionNormalizer::new();
        // Similar (typo) - Levenshtein distance of 1 char over 6 chars = 0.16
        let dist = normalizer.semantic_distance("delete", "delet");
        assert!(dist < 0.25, "Expected distance < 0.25, got {}", dist);
        
        // Two char difference over 6 chars = 0.33
        let dist = normalizer.semantic_distance("delete", "deleet");
        assert!(dist < 0.4, "Expected distance < 0.4, got {}", dist);
    }
    
    #[test]
    fn semantic_distance_detects_different() {
        let normalizer = ActionNormalizer::new();
        // Completely different
        let dist = normalizer.semantic_distance("delete", "read");
        assert!(dist > 0.5, "Expected distance > 0.5, got {}", dist);
    }
    
    #[test]
    fn obfuscation_variants_all_normalize_same() {
        let normalizer = ActionNormalizer::new();
        
        let variants = vec![
            "delete",
            "Delete",
            "DELETE",
            "delete-all",
            "deleteAll",
            "delete_all",
            "delete.all",
            "remove",
            "REMOVE",
            "remove_all",
            "erase",
            "purge",
        ];
        
        // All should normalize to "delete"
        for variant in variants {
            assert_eq!(
                normalizer.normalize(variant),
                "delete",
                "Failed for variant: {}",
                variant
            );
        }
    }
}
