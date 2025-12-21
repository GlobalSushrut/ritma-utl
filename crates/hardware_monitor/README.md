# Hardware-Level Monitoring

Truthful-by-default. This crate models CPU perf counters, memory controller events, and PCIe scanning. It analyzes counters and events supplied by the caller; it does not read MSRs/PCI config space by itself.

## What it detects

- CPU anomalies: branch prediction spikes (Spectre-like), cache timing anomalies
- Memory: Rowhammer attempts (excessive row accesses)
- PCIe: unauthorized/DMA-capable/suspicious vendor devices

## Key types

- `HardwareMonitor`
  - `cpu_monitor()` -> `CpuPerformanceMonitor`
  - `memory_monitor()` -> `MemoryControllerMonitor`
  - `pcie_monitor()` -> `PcieDeviceMonitor`
  - `get_hardware_report()` -> aggregates alerts and suspicious devices

Evidence/alerts:
- `HardwareAnomalyAlert { anomaly_type, evidence: HardwareEvidence{ counter_values, baseline_deviation, affected_cores, ... } }`
- Suspicious `PcieDeviceInfo { vendor_id, dma_enabled, is_authorized, ... }`

## Usage

```rust
use hardware_monitor::{HardwareMonitor, CpuPerformanceCounters, MemoryControllerEvent, MemoryEventType, PcieDeviceInfo};

let mut hwm = HardwareMonitor::new(0.5, 1000); // cpu_threshold, rowhammer_threshold

// CPU
hwm.cpu_monitor().establish_baseline(0, CpuPerformanceCounters {
    core_id:0, cycles:1_000_000, instructions:800_000, cache_misses:1_000, cache_references:10_000,
    branch_misses:100, branch_instructions:10_000, page_faults:10, context_switches:5,
});
let _cpu_alert = hwm.cpu_monitor().monitor_counters(CpuPerformanceCounters {
    core_id:0, cycles:1_000_000, instructions:800_000, cache_misses:1_000, cache_references:10_000,
    branch_misses:5_000, branch_instructions:10_000, page_faults:10, context_switches:5,
});

// Memory (Rowhammer)
for _ in 0..1500 {
    hwm.memory_monitor().record_event(MemoryControllerEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: MemoryEventType::RowhammerAttempt,
        address: 0x1000, value: 0, channel: 0,
    });
}

// PCIe
let suspicious = PcieDeviceInfo { bus:0, device:1, function:0, vendor_id:0xFFFF, device_id:0x1234,
    class_code:0x020000, is_authorized:false, dma_enabled:true, suspicious:false, suspicious_reasons:vec![] };
let _ = hwm.pcie_monitor().scan_device(suspicious);
```

## Reporting

```rust
let report = hwm.get_hardware_report();
// report.hardware_alerts, report.suspicious_devices
```

## Truthful-by-default
- Library analyzes readouts you provide; it does not claim direct hardware access.
- Anomalies and evidence mirror the supplied counters and events.

## Testing

```bash
cargo test -p hardware_monitor
```
