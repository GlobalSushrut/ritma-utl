/// Input validation utilities for Ritma CLI
use std::path::Path;

/// Validate a namespace string: must be non-empty and start with "ns://"
pub fn validate_namespace(ns: &str) -> Result<(), String> {
    if ns.is_empty() {
        return Err("namespace cannot be empty".to_string());
    }
    if !ns.starts_with("ns://") {
        return Err("namespace must start with 'ns://'".to_string());
    }
    if ns.len() < "ns://a".len() {
        return Err("namespace too short".to_string());
    }
    // Optional: enforce reasonable length
    if ns.len() > 512 {
        return Err("namespace too long (max 512 chars)".to_string());
    }
    Ok(())
}

/// Validate a file path is within safe bounds (no absolute paths unless allowed)
pub fn validate_path_allowed(path: &Path, allow_absolute: bool) -> Result<(), String> {
    if path.is_absolute() && !allow_absolute {
        return Err("absolute paths not allowed".to_string());
    }
    // Prevent path traversal attempts
    if let Some(s) = path.to_str() {
        if s.contains("..") {
            return Err("path traversal not allowed".to_string());
        }
    }
    Ok(())
}

/// Validate a port number is within 1-65535
pub fn validate_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("port cannot be 0".to_string());
    }
    // Well-known privileged ports 1-1023 are generally not allowed for non-root
    if port < 1024 {
        // Allow if explicitly intended; otherwise warn
        // For now, allow but could be restricted
    }
    Ok(())
}

/// Validate a Unix timestamp is within reasonable range (year 1970-2100)
pub fn validate_timestamp(ts: i64) -> Result<(), String> {
    if ts < 0 {
        return Err("timestamp cannot be negative".to_string());
    }
    // Approximate max for year 2100
    const MAX_TS: i64 = 4102444800;
    if ts > MAX_TS {
        return Err("timestamp too far in the future".to_string());
    }
    Ok(())
}

/// Validate a limit/count is reasonable (1..=10000)
pub fn validate_limit(limit: u32) -> Result<(), String> {
    if limit == 0 {
        return Err("limit cannot be 0".to_string());
    }
    if limit > 10000 {
        return Err("limit too large (max 10000)".to_string());
    }
    Ok(())
}

/// Validate an index_db path has .sqlite extension
pub fn validate_index_db_path(path: &Path) -> Result<(), String> {
    if let Some(ext) = path.extension() {
        if ext != "sqlite" {
            return Err("index_db must have .sqlite extension".to_string());
        }
    } else {
        return Err("index_db must have .sqlite extension".to_string());
    }
    Ok(())
}

/// Validate a tenant ID: alphanumeric with limited symbols
pub fn validate_tenant_id(tenant: &str) -> Result<(), String> {
    if tenant.is_empty() {
        return Err("tenant ID cannot be empty".to_string());
    }
    if tenant.len() > 128 {
        return Err("tenant ID too long (max 128)".to_string());
    }
    // Allow alphanumeric, dash, underscore, dot
    for ch in tenant.chars() {
        if !ch.is_alphanumeric() && !matches!(ch, '-' | '_' | '.') {
            return Err(format!("invalid character '{ch}' in tenant ID"));
        }
    }
    Ok(())
}

/// Validate a DID string (basic check)
pub fn validate_did(did: &str) -> Result<(), String> {
    if did.is_empty() {
        return Err("DID cannot be empty".to_string());
    }
    if !did.starts_with("did:") {
        return Err("DID must start with 'did:'".to_string());
    }
    if did.len() > 2048 {
        return Err("DID too long".to_string());
    }
    Ok(())
}

/// Validate a hex string (even length, hex chars only)
pub fn validate_hex_string(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("hex string cannot be empty".to_string());
    }
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    for ch in s.chars() {
        if !ch.is_ascii_hexdigit() {
            return Err(format!("invalid hex character '{ch}'"));
        }
    }
    Ok(())
}

/// Validate a key spec "type:hex"
pub fn validate_key_spec(spec: &str) -> Result<(), String> {
    let parts: Vec<&str> = spec.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("key spec must be format 'type:hex'".to_string());
    }
    let typ = parts[0].trim();
    let hex = parts[1].trim();
    if typ.is_empty() || hex.is_empty() {
        return Err("both type and hex required in key spec".to_string());
    }
    // Validate key type
    match typ {
        "hmac" | "hmac_sha256" | "ed25519" => {}
        _ => return Err(format!("unsupported key type '{typ}'")),
    }
    validate_hex_string(hex)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_namespace() {
        assert!(validate_namespace("ns://abc").is_ok());
        assert!(validate_namespace("ns://demo/dev/hello/world").is_ok());
        assert!(validate_namespace("").is_err());
        assert!(validate_namespace("abc").is_err());
        assert!(validate_namespace("ns://").is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_timestamp() {
        assert!(validate_timestamp(0).is_ok());
        assert!(validate_timestamp(1700000000).is_ok());
        assert!(validate_timestamp(-1).is_err());
        assert!(validate_timestamp(9999999999).is_err());
    }

    #[test]
    fn test_validate_limit() {
        assert!(validate_limit(10).is_ok());
        assert!(validate_limit(10000).is_ok());
        assert!(validate_limit(0).is_err());
        assert!(validate_limit(10001).is_err());
    }

    #[test]
    fn test_validate_tenant_id() {
        assert!(validate_tenant_id("tenant123").is_ok());
        assert!(validate_tenant_id("my-tenant.org").is_ok());
        assert!(validate_tenant_id("").is_err());
        assert!(validate_tenant_id("tenant@bad").is_err());
    }

    #[test]
    fn test_validate_did() {
        assert!(validate_did("did:example:123456").is_ok());
        assert!(validate_did("").is_err());
        assert!(validate_did("example:123").is_err());
    }

    #[test]
    fn test_validate_hex_string() {
        assert!(validate_hex_string("deadbeef").is_ok());
        assert!(validate_hex_string("0123456789abcdef").is_ok());
        assert!(validate_hex_string("").is_err());
        assert!(validate_hex_string("xyz").is_err());
        assert!(validate_hex_string("abc").is_err()); // odd length
    }

    #[test]
    fn test_validate_key_spec() {
        assert!(validate_key_spec("hmac:deadbeef").is_ok());
        assert!(validate_key_spec(
            "ed25519:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        .is_ok());
        assert!(validate_key_spec("hmac").is_err());
        assert!(validate_key_spec("unknown:deadbeef").is_err());
    }
}
