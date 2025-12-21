# Ritma Kubernetes Deployment

This directory contains Kubernetes manifests for deploying Ritma as a distributed, non-custodial governance substrate.

## Quick Start

### Using ritma CLI (Recommended)

```bash
# Generate K8s manifests with custom namespace
ritma init --mode k8s --namespace "ns://your/namespace"

# Deploy to K8s cluster
ritma up --mode k8s
```

### Manual Deployment

```bash
# Apply all manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n ritma-system

# View logs
kubectl logs -n ritma-system -l app=tracer-sidecar
kubectl logs -n ritma-system -l app=bar-orchestrator
```

## Components

### 1. **namespace.yaml**
Creates the `ritma-system` namespace for all Ritma components.

### 2. **redis.yaml**
- Redis service for caching and coordination
- Single replica deployment
- No persistence (appendonly disabled)

### 3. **utld.yaml**
- Universal Tamper-proof Ledger Daemon
- Provides receipt sealing and chain continuity
- Exposed on port 8088

### 4. **tracer-daemonset.yaml**
- Runs on every node as a DaemonSet
- Privileged container with host PID/network access
- Monitors:
  - auditd logs (`/var/log/audit/audit.log`)
  - `/proc/net/tcp` for egress connections
- Privacy mode: `hash-only` by default
- Data persisted to `/var/ritma/data` on host

### 5. **orchestrator.yaml**
- BAR (Behavioral Analysis & Response) orchestrator
- Single replica deployment
- Runs ML scoring, judging, and proof sealing
- Connects to UTLD for receipt generation
- 60-second window ticks (configurable via `TICK_SECS`)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  ritma-system                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────┐    ┌──────────────┐   ┌──────────┐  │
│  │  Redis   │◄───┤ Orchestrator │──►│   UTLD   │  │
│  └──────────┘    └──────────────┘   └──────────┘  │
│                          ▲                          │
│                          │                          │
│                  ┌───────┴────────┐                 │
│                  │ Tracer (DaemonSet)               │
│                  │  - auditd tail                   │
│                  │  - /proc scanner                 │
│                  │  - privacy engine                │
│                  └──────────────────┘               │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

**Tracer:**
- `NAMESPACE_ID`: Tenant namespace (default: `ns://k8s/default`)
- `PRIVACY_MODE`: `hash-only` or `raw` (default: `hash-only`)
- `AUDIT_LOG_PATH`: Path to auditd log
- `INDEX_DB_PATH`: SQLite database path
- `PROC_ROOT`: /proc mount point

**Orchestrator:**
- `NAMESPACE_ID`: Tenant namespace
- `TICK_SECS`: Window interval in seconds (default: 60)
- `UTLD_URL`: UTLD service endpoint
- `INDEX_DB_PATH`: SQLite database path

**UTLD:**
- `NAMESPACE_ID`: Tenant namespace

### Customization

Edit the YAML files to:
- Change namespace from `ns://k8s/default`
- Adjust resource limits/requests
- Modify storage (use PVC instead of hostPath)
- Configure node selectors/tolerations
- Add TLS/mTLS for UTLD

## Storage

By default, data is stored on the host at `/var/ritma/data`. For production:

```yaml
volumes:
- name: data
  persistentVolumeClaim:
    claimName: ritma-data-pvc
```

## Security Considerations

1. **Privileged Tracer**: Required for auditd and /proc access
2. **Host Mounts**: Tracer needs host PID, network, and filesystem access
3. **RBAC**: Apply appropriate RBAC policies for production
4. **Network Policies**: Restrict traffic between components
5. **Secrets**: Use K8s secrets for sensitive config

## Monitoring

```bash
# Check all pods
kubectl get pods -n ritma-system -o wide

# View tracer logs on specific node
kubectl logs -n ritma-system -l app=tracer-sidecar --tail=100

# View orchestrator logs
kubectl logs -n ritma-system -l app=bar-orchestrator --tail=100 -f

# Exec into orchestrator for debugging
kubectl exec -it -n ritma-system deployment/bar-orchestrator -- /bin/sh
```

## Cleanup

```bash
# Delete all Ritma resources
kubectl delete -f k8s/

# Or delete namespace (removes everything)
kubectl delete namespace ritma-system
```

## Production Checklist

- [ ] Configure persistent volumes (PVC)
- [ ] Set resource limits and requests
- [ ] Enable RBAC and network policies
- [ ] Configure TLS for UTLD
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Configure log aggregation
- [ ] Review security context and capabilities
- [ ] Set up backup for IndexDB
- [ ] Configure node affinity/anti-affinity
- [ ] Enable pod disruption budgets
