# Ritma Python SDK

Python SDK for configuring and deploying Ritma forensic security platform.

## Installation

```bash
pip install ritma
```

## Quick Start

### Load and Deploy Configuration

```python
from ritma import RitmaConfig, RitmaClient

# Load from YAML
config = RitmaConfig.from_yaml("ritma.yaml")

# Deploy
client = RitmaClient(config)
client.deploy()
```

### Create Configuration Programmatically

```python
from ritma import RitmaConfig, CaptureConfig, MLConfig, ComplianceConfig
from ritma.models import PrivacyMode, MLModel, ComplianceFramework

config = RitmaConfig(
    namespace="my-app-prod",
    capture=CaptureConfig(
        window_seconds=300,
        privacy_mode=PrivacyMode.FULL,
        watch_paths=["/etc/passwd", "/var/log/auth.log"],
    ),
    ml=MLConfig(
        enabled=True,
        threshold=0.7,
        models=[MLModel.ANOMALY, MLModel.BEHAVIOR],
    ),
    compliance=ComplianceConfig(
        frameworks=[ComplianceFramework.PIPEDA, ComplianceFramework.SOX],
    ),
)

# Export to YAML
config.to_yaml("ritma.yaml")

# Deploy
client = RitmaClient(config)
client.deploy()
```

### Generate Kubernetes Manifests

```python
from ritma import RitmaConfig, RitmaClient
from ritma.models import DeployType, DeployConfig

config = RitmaConfig.from_yaml("ritma.yaml")
config.deploy = DeployConfig(type=DeployType.KUBERNETES, replicas=3)

client = RitmaClient(config)
k8s_manifest = client._deploy_kubernetes()

with open("ritma-k8s.yaml", "w") as f:
    f.write(k8s_manifest)
```

### Capture and Verify

```python
from ritma import RitmaConfig, RitmaClient

config = RitmaConfig.from_yaml("ritma.yaml")
client = RitmaClient(config)

# Capture events for 60 seconds
client.capture(duration=60, output="./evidence")

# Verify proofpack
is_valid = client.verify("./evidence/proofpack")
print(f"Proofpack valid: {is_valid}")
```

## Configuration Reference

See [ritma.example.yaml](../../schemas/ritma.example.yaml) for full configuration options.

## License

Apache 2.0
