use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::os::unix::fs::PermissionsExt;

use chrono::{Datelike, NaiveDateTime};

/// Persist a DigFile JSON blob to a local filesystem "forensics" tree
/// using an S3-style layout:
///
///   forensics/<tenant_id>/<YYYY>/<MM>/<DD>/root-<root_id>_file-<file_id>_<timestamp>.dig.json
///
/// The base directory is controlled by `UTLD_FORENSICS_DIR` and defaults to `./forensics`.
/// Returns the full storage path as a string on success.
pub fn persist_dig_to_fs(
    tenant_id: Option<&str>,
    root_id: u128,
    file_id: u128,
    time_start: u64,
    time_end: u64,
    dig_json: &str,
) -> std::io::Result<String> {
    let base = std::env::var("UTLD_FORENSICS_DIR").unwrap_or_else(|_| "./forensics".to_string());
    let tenant = tenant_id.unwrap_or("unknown");

    // Use end of time range as the canonical timestamp for the object key.
    let ts = time_end.max(time_start);
    let dt = NaiveDateTime::from_timestamp_opt(ts as i64, 0)
        .unwrap_or_else(|| NaiveDateTime::from_timestamp_opt(0, 0).unwrap());
    let (year, month, day) = (dt.year(), dt.month(), dt.day());

    let mut path = PathBuf::from(base);
    path.push(tenant);
    path.push(format!("{:04}", year));
    path.push(format!("{:02}", month));
    path.push(format!("{:02}", day));
    fs::create_dir_all(&path)?;

    if let Ok(meta) = fs::metadata(&path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o750);
        let _ = fs::set_permissions(&path, perms);
    }

    let filename = format!(
        "root-{}_file-{}_{}.dig.json",
        root_id, file_id, ts
    );
    path.push(&filename);

    let mut file = File::create(&path)?;
    file.write_all(dig_json.as_bytes())?;
    file.sync_all()?;

    Ok(path.to_string_lossy().into_owned())
}
