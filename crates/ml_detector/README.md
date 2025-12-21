# ML Detector

Truthful-by-default. This crate provides behavioral anomaly detection, automated threat hunting, and predictive security. It operates on feature vectors and evidence supplied by the caller.

## What it detects

- Behavioral anomalies from feature vectors (process/network/filesystem/syscall mix)
- Automated hunts against simple hypotheses (e.g., Living off the Land)
- Predictive alerts based on precursor patterns (conservative wording recommended)

## Key types

- `MlDetector`
  - `behavioral_detector()` -> `BehavioralAnomalyDetector`
  - `threat_hunter()` -> `AutomatedThreatHunter`
  - `predictive_engine()` -> `PredictiveSecurityEngine`
  - `get_ml_report()` -> aggregates anomalies, hunts, predictions

Evidence/alerts:
- `MlAnomalyAlert { anomaly_type, confidence, features[]{name,value,importance} }`
- `ThreatHuntingResult { hypothesis, findings[], confidence, threat_score }`
- `PredictiveAlert { predicted_threat, probability, time_to_threat, precursors }`

## Usage

```rust
use ml_detector::{MlDetector, BehavioralFeatureVector};

let mut mld = MlDetector::new(0.7);

// Train on normal behavior
mld.behavioral_detector().train(vec![
    BehavioralFeatureVector { process_creation_rate:1.0, network_connection_rate:2.0, file_modification_rate:0.5, syscall_diversity:0.3, memory_allocation_rate:1.5, cpu_usage:0.2, io_operations:10.0 },
    BehavioralFeatureVector { process_creation_rate:1.1, network_connection_rate:2.1, file_modification_rate:0.6, syscall_diversity:0.35, memory_allocation_rate:1.6, cpu_usage:0.25, io_operations:11.0 },
]);

// Detect anomaly
let anomalous = BehavioralFeatureVector { process_creation_rate:50.0, network_connection_rate:100.0, file_modification_rate:20.0, syscall_diversity:0.9, memory_allocation_rate:50.0, cpu_usage:0.9, io_operations:1000.0 };
let _anomaly = mld.behavioral_detector().detect_anomaly(anomalous);

// Hunt
let mut evidence = std::collections::HashMap::new();
evidence.insert("powershell.exe".to_string(), vec!["cmd1".to_string(), "cmd2".to_string()]);
let _hunt = mld.threat_hunter().hunt("Living off the Land", &evidence);

// Predict
let precursors = vec!["reconnaissance".to_string(), "credential_access".to_string(), "lateral_movement".to_string()];
let _pred = mld.predictive_engine().predict_threat(&precursors);
```

## Reporting

```rust
let report = mld.get_ml_report();
// report.anomalies, report.hunt_results, report.predictions
```

## Truthful-by-default
- Use conservative phrasing for predictions (e.g., "ransomware-like behavior risk" + horizon) unless you wire your own model semantics.
- The library does not claim to identify named actors.

## Testing

```bash
cargo test -p ml_detector
```
