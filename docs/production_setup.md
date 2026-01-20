# Ritma Production Setup (Systemd + Kubernetes + Docker)

Goal: a real-world standard setup experience:

- **one config file**: `ritma.yaml` (portable across Python / TypeScript / Rust tooling)
- **one deployment generator**: `ritma deploy ...` (templates)
- **one evidence contract**: capture → seal → export (ProofPacks)

This document is operator-focused and matches the **current CLI behavior**.

---

## 1) The single config file: `ritma.yaml`

### 1.1 Minimal example (current)

```yaml
version: "1.0"
namespace: "ns://acme/prod/app"

node:
  id: "node-001"
  labels:
    environment: "production"

storage:
  base_dir: "/var/lib/ritma"
  out_dir: "/var/lib/ritma/out"
  cas_enabled: true

capture:
  window_seconds: 300
  privacy_mode: "full"  # full | redacted | minimal

ml:
  enabled: true
  threshold: 0.7

deploy:
  type: "systemd" # systemd | kubernetes | docker | standalone
```

Where this is used today:

- **SDKs** (Python/TS) can load/validate/generate env files and deployment manifests from `ritma.yaml`.
- **Runtime binaries** (`ritma-sidecar`) currently consume configuration primarily via **environment variables** and `/etc/ritma/ritma.conf`.

Tip: see `schemas/ritma.example.yaml` for a complete example.

### 1.2 Regulated example (suggested pattern)

Ritma supports privacy modes at capture time. A common regulated posture is:

- Default to `privacy_mode: redacted` or `minimal`
- Use short, time-bounded overrides when investigating an active incident

(Exact “break-glass” workflow enforcement is environment-specific.)

---

## 2) Installation

### 2.1 Debian/Ubuntu (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/ritma-io/ritma/main/scripts/setup-apt.sh | sudo bash
sudo apt install ritma
```

This installs:

- `ritma` (CLI)
- `ritma-sidecar` (capture daemon)
- `/etc/ritma/ritma.conf` (env config)

### 2.2 From source (developer)

```bash
cargo build --release -p ritma_cli -p tracer_sidecar
sudo ./install.sh
```

## 3) Systemd setup (Linux hosts)

### 3.1 Configure

Edit:

- `/etc/ritma/ritma.conf` (environment variables)

Minimum recommended values:

```bash
RITMA_NODE_ID=node-001
RITMA_BASE_DIR=/var/lib/ritma
RITMA_OUT_ENABLE=1
RITMA_CAS_ENABLE=1
RUST_LOG=ritma=info
```

### 3.2 Start the sidecar

```bash
sudo systemctl daemon-reload
sudo systemctl enable ritma-sidecar
sudo systemctl start ritma-sidecar
sudo systemctl status ritma-sidecar
```

### 3.3 Verify capture is working

The sidecar writes to IndexDB. You can sanity-check with:

```bash
ritma doctor --index-db /var/lib/ritma/index_db.sqlite --namespace ns://acme/prod/app
```

## 4) Docker setup (compose)

### 4.1 Generate templates

```bash
ritma deploy export --out ./deploy-out --namespace ns://acme/prod/app
```

Expected output is a set of deploy templates under `./deploy-out/`.

### 4.2 Run

```bash
ritma up --help
ritma ps --help
ritma logs --help
```

### 4.3 Stop

```bash
ritma down --help
```

---

## 5) Kubernetes setup

### 5.1 Generate manifests

```bash
ritma deploy k8s --dir ./deploy-out/k8s --namespace ns://acme/prod/app
```

Expected output is a set of Kubernetes YAML templates under `./deploy-out/k8s/`.

### 5.2 Apply

```bash
kubectl apply -f ./deploy-out/k8s/
```

### 5.3 Observe

```bash
kubectl get pods -A | grep ritma
kubectl logs -A -l app=ritma-sidecar --tail=200
```

### 5.4 Verify it’s capturing

Use `ritma doctor` against the IndexDB path you mounted:

```bash
ritma doctor --index-db /data/index_db.sqlite --namespace ns://acme/prod/app
```

---

## 6) Production operations (day-2)

### 6.1 Seal a window (strict / production)

```bash
ritma seal-window --namespace <ns> --start <unix_seconds> --end <unix_seconds> --strict
```

Notes:

- `--strict` fails if the window has zero trace events.
- `--demo-mode` exists for testing, but production should prefer the strict path.

### 6.2 Export proof (ProofPack v2)

```bash
ritma export window --namespace <ns> --start <start> --end <end> --out ./proofpacks/window
ritma verify-proof --path ./proofpacks/window
```

### 6.3 Diff (human-readable)

```bash
ritma diff --a <ml_id_baseline> --b <ml_id_incident>
```

---

## 7) Notes on current vs. planned UX

The CLI already provides deploy template generation (`ritma deploy export|systemd|k8s`).

Planned improvements (explicitly not all wired everywhere yet):

1. `ritma deploy export` consumes `ritma.yaml` directly (single source of truth)
2. `ritma deploy validate` performs host readiness checks (paths, permissions, kernel capability)
3. Signed ProofPacks by default when a node keystore is configured
