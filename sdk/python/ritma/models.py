"""Ritma configuration models."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class PrivacyMode(str, Enum):
    FULL = "full"
    REDACTED = "redacted"
    MINIMAL = "minimal"


class DeployType(str, Enum):
    STANDALONE = "standalone"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"
    SYSTEMD = "systemd"


class AlertChannel(str, Enum):
    WEBHOOK = "webhook"
    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MLModel(str, Enum):
    ANOMALY = "anomaly"
    BEHAVIOR = "behavior"
    THREAT = "threat"
    COMPLIANCE = "compliance"


class ComplianceFramework(str, Enum):
    PIPEDA = "pipeda"
    SOX = "sox"
    HIPAA = "hipaa"
    PCI_DSS = "pci-dss"
    GDPR = "gdpr"
    LAW25 = "law25"


@dataclass
class NodeConfig:
    """Node configuration."""
    id: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class StorageConfig:
    """Storage configuration."""
    base_dir: str = "/var/lib/ritma"
    out_dir: Optional[str] = None
    cas_enabled: bool = True
    retention_days: int = 90


@dataclass
class CaptureConfig:
    """Capture configuration."""
    window_seconds: int = 300
    privacy_mode: PrivacyMode = PrivacyMode.FULL
    watch_paths: List[str] = field(default_factory=list)
    watch_processes: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)


@dataclass
class MLConfig:
    """ML configuration."""
    enabled: bool = True
    threshold: float = 0.7
    models: List[MLModel] = field(default_factory=lambda: [MLModel.ANOMALY, MLModel.BEHAVIOR])


@dataclass
class AlertChannelConfig:
    """Alert channel configuration."""
    type: AlertChannel
    url: Optional[str] = None
    email: Optional[str] = None
    severity: Severity = Severity.HIGH


@dataclass
class AlertConfig:
    """Alert configuration."""
    enabled: bool = False
    channels: List[AlertChannelConfig] = field(default_factory=list)


@dataclass
class ComplianceConfig:
    """Compliance configuration."""
    frameworks: List[ComplianceFramework] = field(default_factory=list)
    audit_log: bool = True


@dataclass
class ResourceConfig:
    """Resource limits."""
    memory: str = "256Mi"
    cpu: str = "100m"


@dataclass
class DeployConfig:
    """Deployment configuration."""
    type: DeployType = DeployType.SYSTEMD
    replicas: int = 1
    resources: ResourceConfig = field(default_factory=ResourceConfig)
