# Network Traffic Analysis

Truthful-by-default. This crate provides DPI, protocol anomaly detection, and encrypted traffic fingerprinting. It analyzes payloads and flow features supplied by the caller; it does not capture packets by itself.

## What it detects

- DPI: signatures, suspicious substrings, and simple shellcode patterns
- Protocol anomalies: deviations from learned baselines (size/frequency)
- Encrypted traffic fingerprints: JA3/JA3S-like hashes, covert timing/size patterns

## Key types

- `NetworkAnalysisManager`
  - `dpi()` -> `DeepPacketInspector`
  - `anomaly_detector()` -> `ProtocolAnomalyDetector`
  - `fingerprinter()` -> `EncryptedTrafficFingerprinter`
  - `get_analysis_report()` -> aggregates results

Evidence/alerts:
- `DpiAlert { threat_type, evidence: DpiEvidence{ payload_hash, matched_signatures, suspicious_patterns, ... } }`
- `ProtocolAnomalyAlert { anomaly_type, baseline_deviation, ... }`
- `EncryptedTrafficFingerprint { ja3_hash, application_guess, is_suspicious, suspicious_reasons }`

## Usage

```rust
use network_analysis::NetworkAnalysisManager;

let mut nam = NetworkAnalysisManager::new();

// DPI
nam.dpi().add_signature("test_malware".into(), vec![0xde,0xad,0xbe,0xef]);
let payload = [0x00,0x01,0xde,0xad,0xbe,0xef,0x02];
let _dpi = nam.dpi().inspect_payload("192.168.1.100".into(), "evil.com".into(), "TCP".into(), &payload);

// Protocol anomaly
nam.anomaly_detector().learn_baseline("HTTP".into(), &[100,110,90,105,95], &[1.0,1.1,0.9,1.05,0.95]);
let _an = nam.anomaly_detector().detect_anomaly("HTTP", 5000, 1.0);

// Encrypted traffic fingerprinting
let _fp = nam.fingerprinter().fingerprint_traffic(
    "192.168.1.100".into(), "1.2.3.4".into(), Some("TLS1.3".into()), Some("AES256".into()),
    vec![1000,1100,1200,1300], vec![100,100,100,100],
);
```

## Reporting

```rust
let report = nam.get_analysis_report();
// report.dpi_alerts, report.anomaly_alerts, report.suspicious_fingerprints
```

## Truthful-by-default
- Library inspects data you supply; it does not claim live packet capture.
- Evidence hashes and classifications correspond to provided inputs.

## Testing

```bash
cargo test -p network_analysis
```
