# Ritma Lab: 5 Niche Scenario Approach

> **Purpose**: Define production-grade Ritma deployment for 5 high-value niche scenarios that demonstrate real-world enterprise value.

---

## Table of Contents

1. [Scenario 1: AI/ML Audit Trail](#scenario-1-aiml-audit-trail)
2. [Scenario 2: Network Security Monitoring](#scenario-2-network-security-monitoring)
3. [Scenario 3: Ransomware Attack & Forensic Tracking](#scenario-3-ransomware-attack--forensic-tracking)
4. [Scenario 4: Healthcare PHI Access Monitoring](#scenario-4-healthcare-phi-access-monitoring)
5. [Scenario 5: Financial Transaction Audit](#scenario-5-financial-transaction-audit)
6. [Cross-Scenario Ritma Deployment](#cross-scenario-ritma-deployment)
7. [Implementation Priority](#implementation-priority)

---

## Scenario 1: AI/ML Audit Trail

### Business Context

**Regulatory Drivers**:
- **EU AI Act** (2024): High-risk AI systems require logging of inputs, outputs, and decision rationale
- **Canada AIDA** (proposed): AI transparency requirements for automated decision systems
- **SOC 2 Type II**: AI systems handling customer data need audit trails

**Enterprise Pain Points**:
- "Why did the model reject this loan application?"
- "Can we prove the model wasn't biased in hiring decisions?"
- "What data was used to train this version?"

### Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI INFERENCE LAB                             │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐         │
│  │   API-GW     │───▶│   ML-API     │───▶│   MODEL      │         │
│  │  (requests)  │    │  (inference) │    │  (LLM/ML)    │         │
│  └──────────────┘    └──────────────┘    └──────────────┘         │
│         │                   │                   │                  │
│         │                   │                   │                  │
│  ┌──────▼───────────────────▼───────────────────▼──────┐          │
│  │                   RITMA AGENTS                       │          │
│  │  • Request/Response logging                          │          │
│  │  • Model version tracking                            │          │
│  │  • Input feature hashing                             │          │
│  │  • Output decision capture                           │          │
│  │  • Guardrail trigger events                          │          │
│  └─────────────────────────────────────────────────────┘          │
│                             │                                       │
│                             ▼                                       │
│  ┌─────────────────────────────────────────────────────┐          │
│  │              RITMA PROOFPACK                         │          │
│  │  • Tamper-evident inference log                      │          │
│  │  • Model lineage chain                               │          │
│  │  • Decision audit trail                              │          │
│  └─────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

### Nodes

| Node | Role | Workload | Ritma Capture |
|------|------|----------|---------------|
| `api-gw` | Gateway | nginx + rate limiting | Request routing, auth events |
| `ml-api` | Inference API | Python FastAPI | Inference requests, latency, errors |
| `model` | Model Server | Mock LLM/ML | Predictions, confidence scores, guardrails |

### Events Captured

```yaml
ai_events:
  - type: "InferenceRequest"
    fields:
      request_id: string
      model_id: string
      model_version: string
      input_hash: sha256          # Hash of input features (privacy)
      input_token_count: int
      user_id: string
      session_id: string
      
  - type: "InferenceResponse"
    fields:
      request_id: string
      output_hash: sha256         # Hash of output (privacy)
      output_token_count: int
      latency_ms: int
      confidence_score: float
      decision_type: string       # "approve", "reject", "escalate"
      
  - type: "GuardrailTrigger"
    fields:
      request_id: string
      guardrail_id: string
      guardrail_type: string      # "toxicity", "pii", "jailbreak"
      action_taken: string        # "block", "warn", "log"
      
  - type: "ModelVersionChange"
    fields:
      model_id: string
      old_version: string
      new_version: string
      deployment_id: string
      deployer_id: string
```

### Scenario Script

```yaml
scenario:
  name: "ai_audit_trail"
  description: "AI inference with guardrails, bias detection, and model updates"
  duration_seconds: 120
  
phases:
  - name: "normal_inference"
    start: 0
    duration: 30
    traffic:
      type: "ai_inference"
      rps: 20
      params:
        model: "loan-approval-v1"
        decision_distribution:
          approve: 0.7
          reject: 0.25
          escalate: 0.05
          
  - name: "guardrail_triggers"
    start: 30
    duration: 30
    traffic:
      type: "ai_inference"
      rps: 30
      params:
        model: "loan-approval-v1"
        inject_violations:
          pii_leak: 0.1
          jailbreak_attempt: 0.05
          
  - name: "model_update"
    start: 60
    duration: 10
    events:
      - type: "model_deployment"
        model: "loan-approval-v2"
        
  - name: "post_update_inference"
    start: 70
    duration: 50
    traffic:
      type: "ai_inference"
      rps: 25
      params:
        model: "loan-approval-v2"

assertions:
  - type: "event_count"
    filter: "kind=InferenceRequest"
    min: 2000
    
  - type: "event_count"
    filter: "kind=GuardrailTrigger"
    min: 50
    
  - type: "event_count"
    filter: "kind=ModelVersionChange"
    equals: 1
```

### Ritma Deployment (Production-Grade)

```yaml
ritma_deployment:
  mode: "production"
  
  agents:
    api-gw:
      tier: 1
      capture:
        - http_access_logs
        - rate_limit_events
        
    ml-api:
      tier: 2
      capture:
        - http_access_logs
        - application_logs
        - inference_events
      custom_events:
        - InferenceRequest
        - InferenceResponse
        
    model:
      tier: 2
      capture:
        - application_logs
        - guardrail_events
      custom_events:
        - GuardrailTrigger
        - ModelVersionChange
        
  aggregator:
    window_seconds: 5
    chain_algorithm: "sha256"
    signature_algorithm: "ed25519"
    
  export:
    format: "proofpack"
    include:
      - chain_hashes
      - merkle_proofs
      - public_keys
```

### Demo Story

> "Show me every decision the AI made on loan applications last Tuesday, prove the model version, and demonstrate that guardrails blocked PII leakage."

**Ritma delivers**:
1. Tamper-evident log of 2,000+ inference requests
2. Cryptographic proof of model version at each decision
3. Guardrail trigger events with exact timestamps
4. Offline-verifiable bundle for auditors

---

## Scenario 2: Network Security Monitoring

### Business Context

**Regulatory Drivers**:
- **NIST CSF 2.0**: Continuous monitoring and detection
- **Zero Trust Architecture**: "Never trust, always verify"
- **PCI-DSS 4.0**: Network segmentation and monitoring requirements

**Enterprise Pain Points**:
- "How did the attacker move laterally?"
- "What was the blast radius of the breach?"
- "Can we prove our microsegmentation was working?"

### Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    NETWORK SECURITY LAB                             │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                    SEGMENTED NETWORK                        │    │
│  │                                                             │    │
│  │  ┌─────────┐     ┌─────────┐     ┌─────────┐              │    │
│  │  │  DMZ    │     │  APP    │     │  DATA   │              │    │
│  │  │ ZONE    │────▶│  ZONE   │────▶│  ZONE   │              │    │
│  │  └─────────┘     └─────────┘     └─────────┘              │    │
│  │       │               │               │                    │    │
│  │       ▼               ▼               ▼                    │    │
│  │  ┌─────────┐     ┌─────────┐     ┌─────────┐              │    │
│  │  │  web    │     │  api    │     │  db     │              │    │
│  │  │  proxy  │     │ server  │     │ server  │              │    │
│  │  └─────────┘     └─────────┘     └─────────┘              │    │
│  │                                                             │    │
│  └────────────────────────────────────────────────────────────┘    │
│                             │                                       │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │                   RITMA NETWORK AGENTS                       │   │
│  │  • East-West traffic monitoring                              │   │
│  │  • Connection state tracking                                 │   │
│  │  • DNS query logging                                         │   │
│  │  • Microsegmentation policy enforcement                      │   │
│  │  • Anomaly detection events                                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Nodes

| Node | Zone | Role | Ritma Capture |
|------|------|------|---------------|
| `web-proxy` | DMZ | Reverse proxy | North-South traffic, TLS termination |
| `api-server` | APP | Application | East-West traffic, API calls |
| `db-server` | DATA | Database | Data access, query patterns |

### Events Captured

```yaml
network_events:
  - type: "NetConnect"
    fields:
      src_ip: string
      src_port: int
      dst_ip: string
      dst_port: int
      protocol: string            # tcp, udp
      direction: string           # ingress, egress, east-west
      zone_src: string
      zone_dst: string
      bytes_in: int
      bytes_out: int
      state: string               # established, syn_sent, etc.
      
  - type: "DnsQuery"
    fields:
      query_name: string
      query_type: string          # A, AAAA, CNAME, TXT
      response_ip: string
      response_time_ms: int
      
  - type: "PolicyViolation"
    fields:
      src_zone: string
      dst_zone: string
      policy_id: string
      action: string              # deny, alert
      reason: string
      
  - type: "AnomalyDetected"
    fields:
      anomaly_type: string        # port_scan, lateral_movement, data_exfil
      confidence: float
      affected_hosts: list
      baseline_deviation: float
```

### Scenario Script

```yaml
scenario:
  name: "network_security_monitoring"
  description: "Normal traffic, lateral movement attempt, and detection"
  duration_seconds: 120
  
phases:
  - name: "baseline_traffic"
    start: 0
    duration: 40
    traffic:
      type: "network_normal"
      patterns:
        - src: "web-proxy"
          dst: "api-server"
          rps: 50
        - src: "api-server"
          dst: "db-server"
          rps: 30
          
  - name: "reconnaissance"
    start: 40
    duration: 20
    traffic:
      type: "network_attack"
      patterns:
        - type: "port_scan"
          src: "api-server"
          targets: ["db-server"]
          ports: [22, 3306, 5432, 6379]
          
  - name: "lateral_movement_attempt"
    start: 60
    duration: 20
    traffic:
      type: "network_attack"
      patterns:
        - type: "lateral_movement"
          src: "api-server"
          dst: "db-server"
          method: "ssh_brute_force"
          
  - name: "policy_enforcement"
    start: 80
    duration: 20
    events:
      - type: "policy_block"
        src: "api-server"
        dst: "db-server"
        port: 22
        
  - name: "normal_recovery"
    start: 100
    duration: 20
    traffic:
      type: "network_normal"

chaos:
  - action: "latency"
    target: "api-server"
    start: 50
    duration: 10
    params:
      latency_ms: 200

assertions:
  - type: "event_count"
    filter: "kind=NetConnect"
    min: 5000
    
  - type: "event_count"
    filter: "kind=PolicyViolation"
    min: 10
    
  - type: "event_count"
    filter: "kind=AnomalyDetected AND anomaly_type=lateral_movement"
    min: 1
```

### Ritma Deployment (Production-Grade)

```yaml
ritma_deployment:
  mode: "production"
  
  agents:
    web-proxy:
      tier: 2
      capture:
        - network_flows
        - dns_queries
        - http_access_logs
      network:
        mode: "passive"
        interfaces: ["eth0"]
        
    api-server:
      tier: 2
      capture:
        - network_flows
        - process_network
        - application_logs
      network:
        mode: "passive"
        track_connections: true
        
    db-server:
      tier: 2
      capture:
        - network_flows
        - database_queries
      network:
        mode: "passive"
        alert_on_new_connections: true
        
  aggregator:
    window_seconds: 5
    correlation:
      enabled: true
      fields: ["src_ip", "dst_ip", "trace_id"]
      
  alerting:
    rules:
      - name: "lateral_movement"
        condition: "zone_src != zone_dst AND port IN [22, 3389]"
        severity: "high"
```

### Demo Story

> "Reconstruct the attacker's path from initial compromise to attempted lateral movement. Prove that microsegmentation blocked the attack."

**Ritma delivers**:
1. Complete network flow timeline across all zones
2. Port scan detection with exact timestamps
3. Lateral movement attempt evidence
4. Policy enforcement proof (blocked connections)
5. Cryptographic chain proving no log tampering

---

## Scenario 3: Ransomware Attack & Forensic Tracking

### Business Context

**Regulatory Drivers**:
- **PIPEDA** (Canada): Breach records must be kept for 2 years
- **Québec Law 25**: Confidentiality incident register retained 5 years
- **GDPR Article 33**: 72-hour breach notification with evidence

**Enterprise Pain Points**:
- "When exactly did the encryption start?"
- "Which files were accessed before encryption?"
- "Can we prove our backup wasn't compromised?"

### Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                   RANSOMWARE FORENSICS LAB                          │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                    ATTACK TIMELINE                          │    │
│  │                                                             │    │
│  │  [Initial Access] → [Discovery] → [Lateral] → [Encrypt]   │    │
│  │       t+0            t+30s         t+60s        t+90s      │    │
│  │                                                             │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐         │
│  │   WORKSTATION │───▶│   FILE-SRV   │───▶│   BACKUP     │         │
│  │   (victim)    │    │   (target)   │    │   (safe)     │         │
│  └──────────────┘    └──────────────┘    └──────────────┘         │
│         │                   │                   │                  │
│         ▼                   ▼                   ▼                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   RITMA FORENSIC AGENTS                      │   │
│  │  • Process execution tracking                                │   │
│  │  • File access monitoring                                    │   │
│  │  • Network connection logging                                │   │
│  │  • Privilege escalation detection                            │   │
│  │  • Encryption activity detection                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                             │                                       │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │              FORENSIC PROOFPACK                              │   │
│  │  • Attack timeline reconstruction                            │   │
│  │  • Chain of custody evidence                                 │   │
│  │  • File access audit trail                                   │   │
│  │  • Process genealogy tree                                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Nodes

| Node | Role | Workload | Ritma Capture |
|------|------|----------|---------------|
| `workstation` | Victim endpoint | User simulation + malware | Process exec, file access, network |
| `file-srv` | File server | SMB shares | File access, encryption patterns |
| `backup` | Backup server | Backup service | Access attempts, integrity checks |

### Events Captured

```yaml
forensic_events:
  - type: "ProcExec"
    fields:
      pid: int
      ppid: int
      exe: string
      exe_hash: sha256
      cmdline: string
      cmdline_hash: sha256
      uid: int
      timestamp: datetime
      
  - type: "FileAccess"
    fields:
      path: string
      path_hash: sha256
      operation: string           # read, write, delete, rename
      pid: int
      bytes: int
      inode: int
      
  - type: "FileEncryption"
    fields:
      original_path: string
      encrypted_path: string
      encryption_detected: bool
      entropy_before: float
      entropy_after: float
      pid: int
      
  - type: "PrivilegeEscalation"
    fields:
      pid: int
      old_uid: int
      new_uid: int
      method: string              # sudo, setuid, exploit
      
  - type: "ProcessTree"
    fields:
      root_pid: int
      tree_depth: int
      suspicious_score: float
      child_processes: list
```

### Scenario Script

```yaml
scenario:
  name: "ransomware_forensics"
  description: "Ransomware attack simulation with full forensic capture"
  duration_seconds: 120
  
phases:
  - name: "normal_operations"
    start: 0
    duration: 20
    traffic:
      type: "office_work"
      patterns:
        - user: "employee1"
          actions: ["open_doc", "save_doc", "browse_web"]
          
  - name: "initial_access"
    start: 20
    duration: 10
    events:
      - type: "phishing_payload"
        target: "workstation"
        payload: "invoice.pdf.exe"
        
  - name: "discovery"
    start: 30
    duration: 20
    events:
      - type: "reconnaissance"
        actions:
          - "whoami"
          - "net user"
          - "net share"
          - "dir /s *.doc*"
          
  - name: "lateral_movement"
    start: 50
    duration: 20
    events:
      - type: "lateral"
        src: "workstation"
        dst: "file-srv"
        method: "smb_admin_share"
        
  - name: "encryption"
    start: 70
    duration: 30
    events:
      - type: "ransomware_encryption"
        target: "file-srv"
        file_count: 100
        extensions: [".doc", ".xls", ".pdf"]
        ransom_note: "README_DECRYPT.txt"
        
  - name: "backup_attempt"
    start: 100
    duration: 20
    events:
      - type: "backup_access_blocked"
        src: "workstation"
        dst: "backup"
        result: "denied"

assertions:
  - type: "event_count"
    filter: "kind=ProcExec"
    min: 500
    
  - type: "event_count"
    filter: "kind=FileEncryption"
    min: 100
    
  - type: "timeline_reconstructable"
    description: "Full attack timeline can be reconstructed"
```

### Ritma Deployment (Production-Grade)

```yaml
ritma_deployment:
  mode: "production"
  tier: 3                         # Full forensic capture
  
  agents:
    workstation:
      tier: 3
      capture:
        - process_exec
        - process_exit
        - file_access
        - network_connections
        - privilege_changes
      ebpf:
        enabled: true
        hooks:
          - sys_execve
          - sys_openat
          - sys_connect
          - sys_setuid
          
    file-srv:
      tier: 3
      capture:
        - file_access
        - smb_sessions
        - entropy_monitoring
      alerts:
        - name: "mass_encryption"
          condition: "file_writes > 100/min AND entropy_increase > 0.5"
          
    backup:
      tier: 2
      capture:
        - access_attempts
        - integrity_checks
      alerts:
        - name: "unauthorized_access"
          condition: "src NOT IN allowed_hosts"
          
  aggregator:
    window_seconds: 1             # 1-second windows for forensics
    chain_algorithm: "sha256"
    
  forensics:
    process_tree: true
    file_timeline: true
    network_graph: true
```

### Demo Story

> "Reconstruct the exact attack timeline: when did the phishing payload execute, what files were accessed, when did encryption start, and prove the backup was never compromised."

**Ritma delivers**:
1. Process execution tree from initial payload
2. File access timeline with exact timestamps
3. Encryption detection with entropy analysis
4. Lateral movement evidence
5. Backup access denial proof
6. Court-admissible chain of custody

---

## Scenario 4: Healthcare PHI Access Monitoring

### Business Context

**Regulatory Drivers**:
- **HIPAA Security Rule**: Audit controls for ePHI access
- **PIPEDA/PHIPA** (Canada): Health information protection
- **21 CFR Part 11**: Electronic records integrity

**Enterprise Pain Points**:
- "Who accessed this patient's record and why?"
- "Can we prove minimum necessary access was enforced?"
- "How do we detect unauthorized PHI access?"

### Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HEALTHCARE PHI LAB                               │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                    EHR SYSTEM                               │    │
│  │                                                             │    │
│  │  ┌─────────┐     ┌─────────┐     ┌─────────┐              │    │
│  │  │  PORTAL │────▶│  EHR-API│────▶│ PATIENT │              │    │
│  │  │ (users) │     │ (FHIR)  │     │   DB    │              │    │
│  │  └─────────┘     └─────────┘     └─────────┘              │    │
│  │       │               │               │                    │    │
│  │       ▼               ▼               ▼                    │    │
│  │  ┌─────────────────────────────────────────────────────┐  │    │
│  │  │              RITMA PHI AGENTS                        │  │    │
│  │  │  • User authentication events                        │  │    │
│  │  │  • PHI access logging (who, what, when, why)        │  │    │
│  │  │  • Break-the-glass events                            │  │    │
│  │  │  • Minimum necessary enforcement                     │  │    │
│  │  │  • Anomaly detection (unusual access patterns)       │  │    │
│  │  └─────────────────────────────────────────────────────┘  │    │
│  │                                                             │    │
│  └────────────────────────────────────────────────────────────┘    │
│                             │                                       │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │              HIPAA COMPLIANCE PROOFPACK                      │   │
│  │  • PHI access audit trail                                    │   │
│  │  • User activity reports                                     │   │
│  │  • Break-the-glass justifications                            │   │
│  │  • Minimum necessary compliance proof                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Nodes

| Node | Role | Workload | Ritma Capture |
|------|------|----------|---------------|
| `portal` | User portal | Web UI | Auth events, session tracking |
| `ehr-api` | FHIR API | HL7 FHIR server | PHI access, API calls |
| `patient-db` | Patient database | PostgreSQL | Query logging, data access |

### Events Captured

```yaml
phi_events:
  - type: "UserAuthentication"
    fields:
      user_id: string
      user_role: string           # physician, nurse, admin
      auth_method: string         # password, mfa, sso
      success: bool
      ip_address: string
      
  - type: "PhiAccess"
    fields:
      user_id: string
      user_role: string
      patient_id_hash: sha256     # Never log actual patient ID
      resource_type: string       # Patient, Observation, MedicationRequest
      access_reason: string       # treatment, payment, operations
      fields_accessed: list
      minimum_necessary: bool
      
  - type: "BreakTheGlass"
    fields:
      user_id: string
      patient_id_hash: sha256
      justification: string
      supervisor_id: string
      approved: bool
      
  - type: "PhiAnomaly"
    fields:
      user_id: string
      anomaly_type: string        # unusual_volume, off_hours, wrong_department
      baseline_deviation: float
      alert_level: string
      
  - type: "DataExport"
    fields:
      user_id: string
      patient_count: int
      export_format: string
      destination: string
      approved: bool
```

### Scenario Script

```yaml
scenario:
  name: "healthcare_phi_monitoring"
  description: "Normal clinical workflow with PHI access, break-the-glass, and anomaly"
  duration_seconds: 120
  
phases:
  - name: "normal_clinical_workflow"
    start: 0
    duration: 40
    traffic:
      type: "ehr_access"
      users:
        - role: "physician"
          actions: ["view_patient", "order_medication", "view_labs"]
          patients_per_session: 5
        - role: "nurse"
          actions: ["view_vitals", "document_care"]
          patients_per_session: 10
          
  - name: "break_the_glass"
    start: 40
    duration: 20
    events:
      - type: "emergency_access"
        user: "dr_smith"
        patient: "vip_patient_001"
        justification: "Emergency consultation"
        
  - name: "suspicious_access"
    start: 60
    duration: 30
    traffic:
      type: "ehr_access"
      users:
        - role: "admin"
          actions: ["bulk_export", "view_all_patients"]
          anomaly: true
          
  - name: "anomaly_detection"
    start: 90
    duration: 30
    events:
      - type: "alert_triggered"
        user: "admin_user"
        reason: "Unusual bulk access pattern"

assertions:
  - type: "event_count"
    filter: "kind=PhiAccess"
    min: 500
    
  - type: "event_count"
    filter: "kind=BreakTheGlass"
    min: 1
    
  - type: "event_count"
    filter: "kind=PhiAnomaly"
    min: 1
    
  - type: "phi_never_logged"
    description: "No actual PHI in logs, only hashes"
```

### Ritma Deployment (Production-Grade)

```yaml
ritma_deployment:
  mode: "production"
  compliance: "hipaa"
  
  privacy:
    phi_fields:
      - patient_id
      - patient_name
      - ssn
      - dob
      - address
    action: "hash_sha256"         # Never log PHI, only hashes
    
  agents:
    portal:
      tier: 1
      capture:
        - authentication_events
        - session_tracking
        - access_logs
        
    ehr-api:
      tier: 2
      capture:
        - fhir_requests
        - phi_access_events
        - break_the_glass
      custom_events:
        - PhiAccess
        - BreakTheGlass
        
    patient-db:
      tier: 2
      capture:
        - query_logs
        - data_access
      redaction:
        enabled: true
        fields: ["patient_name", "ssn", "dob"]
        
  aggregator:
    window_seconds: 5
    retention_days: 2190          # 6 years for HIPAA
    
  reporting:
    hipaa_audit_report: true
    minimum_necessary_report: true
    break_the_glass_report: true
```

### Demo Story

> "Generate a HIPAA audit report showing all access to patient X's records, including the emergency break-the-glass access with justification, and prove no unauthorized access occurred."

**Ritma delivers**:
1. Complete PHI access audit trail (hashed patient IDs)
2. Break-the-glass event with justification and approval
3. Minimum necessary compliance proof
4. Anomaly detection for suspicious access
5. 6-year retention with tamper-evident chain

---

## Scenario 5: Financial Transaction Audit

### Business Context

**Regulatory Drivers**:
- **SOX Section 404**: Internal controls over financial reporting
- **PCI-DSS 4.0**: Transaction audit trails
- **MiFID II**: Transaction reporting and order record keeping
- **OSFI B-10** (Canada): Third-party risk management

**Enterprise Pain Points**:
- "Can we prove this transaction was authorized?"
- "What was the exact sequence of events leading to this trade?"
- "How do we demonstrate segregation of duties?"

### Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                   FINANCIAL TRANSACTION LAB                         │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                    TRADING SYSTEM                           │    │
│  │                                                             │    │
│  │  ┌─────────┐     ┌─────────┐     ┌─────────┐              │    │
│  │  │  OMS    │────▶│ MATCHING│────▶│ LEDGER  │              │    │
│  │  │ (orders)│     │ ENGINE  │     │  (DB)   │              │    │
│  │  └─────────┘     └─────────┘     └─────────┘              │    │
│  │       │               │               │                    │    │
│  │       ▼               ▼               ▼                    │    │
│  │  ┌─────────────────────────────────────────────────────┐  │    │
│  │  │              RITMA FINANCIAL AGENTS                  │  │    │
│  │  │  • Order lifecycle tracking                          │  │    │
│  │  │  • Trade execution audit                             │  │    │
│  │  │  • Authorization verification                        │  │    │
│  │  │  • Segregation of duties enforcement                 │  │    │
│  │  │  • Fraud detection signals                           │  │    │
│  │  └─────────────────────────────────────────────────────┘  │    │
│  │                                                             │    │
│  └────────────────────────────────────────────────────────────┘    │
│                             │                                       │
│  ┌──────────────────────────▼──────────────────────────────────┐   │
│  │              SOX/PCI COMPLIANCE PROOFPACK                    │   │
│  │  • Transaction audit trail                                   │   │
│  │  • Authorization chain                                       │   │
│  │  • Segregation of duties proof                               │   │
│  │  • Fraud detection events                                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Nodes

| Node | Role | Workload | Ritma Capture |
|------|------|----------|---------------|
| `oms` | Order Management | Order entry system | Order lifecycle, authorization |
| `matching` | Matching Engine | Trade execution | Execution events, fills |
| `ledger` | Ledger Database | PostgreSQL | Balance changes, settlements |

### Events Captured

```yaml
financial_events:
  - type: "OrderSubmitted"
    fields:
      order_id: string
      user_id: string
      account_id: string
      instrument: string
      side: string                # buy, sell
      quantity: decimal
      price: decimal
      order_type: string          # market, limit
      timestamp_ns: int           # Nanosecond precision
      
  - type: "OrderAuthorized"
    fields:
      order_id: string
      authorizer_id: string
      authorization_level: int
      dual_control: bool
      
  - type: "TradeExecuted"
    fields:
      trade_id: string
      order_id: string
      execution_price: decimal
      execution_quantity: decimal
      counterparty_id: string
      venue: string
      timestamp_ns: int
      
  - type: "BalanceChange"
    fields:
      account_id: string
      instrument: string
      previous_balance: decimal
      new_balance: decimal
      change_reason: string       # trade, deposit, withdrawal
      
  - type: "SegregationViolation"
    fields:
      user_id: string
      action: string
      conflicting_role: string
      blocked: bool
      
  - type: "FraudSignal"
    fields:
      signal_type: string         # wash_trade, spoofing, front_running
      confidence: float
      related_orders: list
```

### Scenario Script

```yaml
scenario:
  name: "financial_transaction_audit"
  description: "Trading workflow with authorization, execution, and fraud detection"
  duration_seconds: 120
  
phases:
  - name: "normal_trading"
    start: 0
    duration: 40
    traffic:
      type: "trading"
      patterns:
        - user: "trader_1"
          orders_per_minute: 10
          instruments: ["AAPL", "GOOGL", "MSFT"]
        - user: "trader_2"
          orders_per_minute: 15
          instruments: ["AMZN", "META"]
          
  - name: "large_order_authorization"
    start: 40
    duration: 20
    events:
      - type: "large_order"
        user: "trader_1"
        amount: 1000000
        requires_authorization: true
        authorizer: "supervisor_1"
        
  - name: "suspicious_pattern"
    start: 60
    duration: 30
    traffic:
      type: "trading"
      patterns:
        - type: "potential_wash_trade"
          user: "trader_3"
          counterparty: "trader_3_alt"
          
  - name: "fraud_detection"
    start: 90
    duration: 30
    events:
      - type: "fraud_alert"
        signal: "wash_trade"
        confidence: 0.85

assertions:
  - type: "event_count"
    filter: "kind=OrderSubmitted"
    min: 1000
    
  - type: "event_count"
    filter: "kind=TradeExecuted"
    min: 800
    
  - type: "event_count"
    filter: "kind=OrderAuthorized AND dual_control=true"
    min: 1
    
  - type: "event_count"
    filter: "kind=FraudSignal"
    min: 1
```

### Ritma Deployment (Production-Grade)

```yaml
ritma_deployment:
  mode: "production"
  compliance: ["sox", "pci-dss", "mifid2"]
  
  timing:
    precision: "nanosecond"       # Required for MiFID II
    clock_sync: "ntp"
    
  agents:
    oms:
      tier: 2
      capture:
        - order_events
        - authorization_events
        - user_actions
      custom_events:
        - OrderSubmitted
        - OrderAuthorized
        
    matching:
      tier: 2
      capture:
        - execution_events
        - matching_events
      custom_events:
        - TradeExecuted
        
    ledger:
      tier: 2
      capture:
        - balance_changes
        - settlement_events
      custom_events:
        - BalanceChange
        
  aggregator:
    window_seconds: 1             # 1-second windows for trading
    chain_algorithm: "sha256"
    
  fraud_detection:
    enabled: true
    rules:
      - name: "wash_trade"
        condition: "buyer_account == seller_account"
      - name: "spoofing"
        condition: "cancel_rate > 0.9 AND order_size > threshold"
        
  reporting:
    sox_audit_report: true
    transaction_report: true
    segregation_of_duties_report: true
```

### Demo Story

> "Show the complete audit trail for trade #12345: who submitted the order, who authorized it, when it executed, and prove segregation of duties was maintained."

**Ritma delivers**:
1. Order-to-settlement audit trail with nanosecond timestamps
2. Authorization chain with dual control proof
3. Segregation of duties enforcement evidence
4. Fraud detection signals
5. SOX/MiFID II compliant reporting

---

## Cross-Scenario Ritma Deployment

### Common Deployment Pattern

All 5 scenarios share a common Ritma deployment architecture:

```yaml
ritma_common:
  # Agent deployment
  agent:
    binary: "/usr/local/bin/ritma-agent"
    config: "/etc/ritma/agent.yaml"
    data_dir: "/var/lib/ritma"
    
  # Aggregator deployment
  aggregator:
    binary: "/usr/local/bin/ritma-aggregator"
    config: "/etc/ritma/aggregator.yaml"
    output_dir: "/var/lib/ritma/output"
    
  # Key management
  keys:
    type: "ed25519"
    storage: "/etc/ritma/keys"
    rotation: "90d"
    
  # Chain configuration
  chain:
    algorithm: "sha256"
    window_seconds: 5
    hour_rollup: true
    
  # Export format
  export:
    format: "proofpack"
    compression: "zstd"
    include:
      - manifest
      - chain
      - windows
      - public_keys
      - verify_report
```

### Scenario-Specific Overrides

| Scenario | Window Size | Tier | Special Features |
|----------|-------------|------|------------------|
| AI Audit | 5s | 2 | Guardrail events, model versioning |
| Network | 5s | 2 | Flow correlation, zone tracking |
| Ransomware | 1s | 3 | eBPF, process tree, entropy |
| Healthcare | 5s | 2 | PHI hashing, break-the-glass |
| Financial | 1s | 2 | Nanosecond timing, fraud detection |

---

## Implementation Priority

### Phase 1: Foundation (Week 1-2)

1. **Common Lab Infrastructure**
   - Docker Compose base
   - Node container template
   - Ritma agent integration
   - Basic traffic generator

2. **Scenario 3: Ransomware** (Highest demo impact)
   - Most visual/dramatic
   - Clear before/after
   - Forensic timeline reconstruction

### Phase 2: Compliance Scenarios (Week 3-4)

3. **Scenario 4: Healthcare**
   - HIPAA compliance demo
   - PHI access logging
   - Break-the-glass workflow

4. **Scenario 5: Financial**
   - SOX/PCI-DSS compliance
   - Transaction audit trail
   - Fraud detection

### Phase 3: Advanced Scenarios (Week 5-6)

5. **Scenario 1: AI Audit**
   - EU AI Act compliance
   - Inference logging
   - Guardrail tracking

6. **Scenario 2: Network**
   - Zero Trust demo
   - Lateral movement detection
   - Microsegmentation proof

---

## Appendix: Regulatory Mapping

| Regulation | Scenario | Key Requirement | Ritma Feature |
|------------|----------|-----------------|---------------|
| EU AI Act | AI | Decision logging | Inference audit trail |
| HIPAA | Healthcare | PHI access audit | Access logging + hashing |
| SOX 404 | Financial | Internal controls | Transaction audit trail |
| PCI-DSS | Financial | Audit trails | Tamper-evident chain |
| PIPEDA | All | Breach records (2yr) | Proofpack retention |
| Québec Law 25 | All | Incident register (5yr) | Long-term archival |
| OSFI B-10 | Financial | Third-party evidence | Vendor audit proofs |
| MiFID II | Financial | Transaction reporting | Nanosecond timestamps |
| NIST CSF | Network | Continuous monitoring | Real-time capture |
| GDPR Art 33 | All | 72hr breach notification | Forensic timeline |

---

*Document Version: 1.0*
*Last Updated: 2024-01-15*
*Author: Ritma Team*
