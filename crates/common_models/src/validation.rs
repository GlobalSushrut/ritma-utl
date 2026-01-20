use regex::Regex;
use std::sync::OnceLock;

/// Validates namespace ID format: ns://org/env/app/service
pub fn validate_namespace_id(ns: &str) -> Result<(), String> {
    static NS_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = NS_REGEX.get_or_init(|| {
        Regex::new(r"^ns://[a-z0-9_-]+/[a-z0-9_-]+/[a-z0-9_-]+/[a-z0-9_-]+$").unwrap()
    });

    if ns.len() > 256 {
        return Err("Namespace ID too long (max 256)".to_string());
    }

    if !regex.is_match(ns) {
        return Err("Invalid namespace format. Expected: ns://org/env/app/service".to_string());
    }

    Ok(())
}

/// Validates file paths - no traversal, no shell chars
pub fn validate_path(path: &str) -> Result<(), String> {
    // No path traversal
    if path.contains("..") {
        return Err("Path traversal not allowed".to_string());
    }

    // No shell metacharacters
    const FORBIDDEN: &[char] = &[
        '$', '`', '\\', '"', '\'', ';', '&', '|', '<', '>', '(', ')', '{', '}', '\n', '\r', '\0',
    ];
    if path.chars().any(|c| FORBIDDEN.contains(&c)) {
        return Err("Invalid characters in path".to_string());
    }

    if path.len() > 4096 {
        return Err("Path too long (max 4096)".to_string());
    }

    Ok(())
}

/// Validates PID is numeric only
pub fn validate_pid(pid: u32) -> Result<(), String> {
    if pid == 0 || pid > 4194304 {
        // Max PID on Linux
        return Err("Invalid PID range".to_string());
    }
    Ok(())
}

/// Sanitizes strings for safe command execution
pub fn sanitize_for_command(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == '/')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_validation() {
        assert!(validate_namespace_id("ns://demo/dev/hello/world").is_ok());
        assert!(validate_namespace_id("ns://tech-giant/prod/api/auth").is_ok());
        assert!(validate_namespace_id("invalid").is_err());
        assert!(validate_namespace_id("ns://../../etc/passwd").is_err());
        assert!(validate_namespace_id("ns://demo/dev").is_err()); // Too few parts
    }

    #[test]
    fn test_path_validation() {
        assert!(validate_path("/home/user/file.txt").is_ok());
        assert!(validate_path("./relative/path").is_ok());
        assert!(validate_path("../traversal").is_err());
        assert!(validate_path("/etc/passwd; rm -rf /").is_err());
        assert!(validate_path("/path/with$(command)").is_err());
    }

    #[test]
    fn test_pid_validation() {
        assert!(validate_pid(1234).is_ok());
        assert!(validate_pid(0).is_err());
        assert!(validate_pid(5000000).is_err());
    }
}
