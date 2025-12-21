# Memory Forensics

Truthful-by-default. This crate provides grounded detectors for kernel/user memory tampering and concealment techniques. It simulates events via library calls; it does not attach kernel hooks by itself.

## What it detects

- Rootkits (syscall hooking, hidden processes)
- Suspicious kernel modules (hash/signature mismatch, unusual load addresses, suspicious names)
- Memory injection (code into a target process)
- DKOM (Direct Kernel Object Manipulation) for process hiding, etc.

## Key types

- `MemoryForensicsManager`
  - `rootkit_detector()` -> `RootkitDetector`
  - `kernel_module_analyzer()` -> `KernelModuleAnalyzer`
  - `memory_injection_detector()` -> `MemoryInjectionDetector`
  - `dkom_detector()` -> `DkomDetector`
  - `get_forensics_report()` -> aggregates all alerts

Evidence/alerts:
- `RootkitAlert { rootkit_type: SyscallHooking, evidence: RootkitEvidence{...} }`
- `MemoryInjectionAlert { target_pid, injected_address, injected_size, ... }`
- `DkomAlert { dkom_type: ProcessHiding, evidence: DkomEvidence{...} }`

## Usage

```rust
use memory_forensics::{MemoryForensicsManager, KernelModuleInfo, ModuleState};

let mut mfm = MemoryForensicsManager::new();

// Rootkit: baseline and hook detection
mfm.rootkit_detector().establish_baseline("sys_read".into(), 0xffffffff81000000);
if let Some(alert) = mfm.rootkit_detector().check_syscall_hooks("sys_read", 0xffffffff82000000) {
    eprintln!("ROOTKIT: {}", alert.description);
}

// Hidden processes
let visible = vec![1,2,3];
let all = vec![1,2,3,666,1337];
let _ = mfm.rootkit_detector().detect_hidden_processes(&visible, &all);

// Kernel module analysis
let suspicious = KernelModuleInfo {
    name: "rootkit_module".into(), size: 4096, load_address: 0xffffffff81000000,
    reference_count: 0, state: ModuleState::Live, signature_valid: false,
    hash: "malicious".into(), suspicious: false, suspicious_reasons: vec![],
};
let _ = mfm.kernel_module_analyzer().analyze_module(suspicious);

// Memory injection
let _inj = mfm.memory_injection_detector().detect_injection(1337, "victim".into(), 0x7fff0000, 4096, Some(666));

// DKOM
let _dkom = mfm.dkom_detector().detect_process_hiding("malware", true, false);
```

## Reporting

```rust
let report = mfm.get_forensics_report();
// report.rootkit_alerts, report.suspicious_modules, report.injection_alerts, report.dkom_alerts
```

## Truthful-by-default
- Library simulates/analyzes events you provide; no live kernel hooks unless wired by a caller.
- Evidence/alerts reflect actual inputs to APIs.

## Testing

```bash
cargo test -p memory_forensics
```
