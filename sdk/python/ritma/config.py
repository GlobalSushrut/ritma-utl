"""Ritma configuration loader and manager."""

import os
import yaml
import json
from pathlib import Path
from dataclasses import asdict
from typing import Optional, Dict, Any

from .models import (
    NodeConfig,
    StorageConfig,
    CaptureConfig,
    MLConfig,
    AlertConfig,
    AlertChannelConfig,
    ComplianceConfig,
    DeployConfig,
    ResourceConfig,
    PrivacyMode,
    DeployType,
    AlertChannel,
    Severity,
    MLModel,
    ComplianceFramework,
)


class RitmaConfig:
    """Ritma configuration manager."""

    def __init__(
        self,
        namespace: str,
        version: str = "1.0",
        node: Optional[NodeConfig] = None,
        storage: Optional[StorageConfig] = None,
        capture: Optional[CaptureConfig] = None,
        ml: Optional[MLConfig] = None,
        alerts: Optional[AlertConfig] = None,
        compliance: Optional[ComplianceConfig] = None,
        deploy: Optional[DeployConfig] = None,
    ):
        self.version = version
        self.namespace = namespace
        self.node = node or NodeConfig()
        self.storage = storage or StorageConfig()
        self.capture = capture or CaptureConfig()
        self.ml = ml or MLConfig()
        self.alerts = alerts or AlertConfig()
        self.compliance = compliance or ComplianceConfig()
        self.deploy = deploy or DeployConfig()

    @classmethod
    def from_yaml(cls, path: str) -> "RitmaConfig":
        """Load configuration from YAML file."""
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return cls._from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RitmaConfig":
        """Load configuration from dictionary."""
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "RitmaConfig":
        """Parse configuration dictionary."""
        node_data = data.get("node", {})
        node = NodeConfig(
            id=node_data.get("id"),
            labels=node_data.get("labels", {}),
        )

        storage_data = data.get("storage", {})
        storage = StorageConfig(
            base_dir=storage_data.get("base_dir", "/var/lib/ritma"),
            out_dir=storage_data.get("out_dir"),
            cas_enabled=storage_data.get("cas_enabled", True),
            retention_days=storage_data.get("retention_days", 90),
        )

        capture_data = data.get("capture", {})
        capture = CaptureConfig(
            window_seconds=capture_data.get("window_seconds", 300),
            privacy_mode=PrivacyMode(capture_data.get("privacy_mode", "full")),
            watch_paths=capture_data.get("watch_paths", []),
            watch_processes=capture_data.get("watch_processes", []),
            exclude_paths=capture_data.get("exclude_paths", []),
        )

        ml_data = data.get("ml", {})
        ml = MLConfig(
            enabled=ml_data.get("enabled", True),
            threshold=ml_data.get("threshold", 0.7),
            models=[MLModel(m) for m in ml_data.get("models", ["anomaly", "behavior"])],
        )

        alerts_data = data.get("alerts", {})
        channels = []
        for ch in alerts_data.get("channels", []):
            channels.append(AlertChannelConfig(
                type=AlertChannel(ch["type"]),
                url=ch.get("url"),
                email=ch.get("email"),
                severity=Severity(ch.get("severity", "high")),
            ))
        alerts = AlertConfig(
            enabled=alerts_data.get("enabled", False),
            channels=channels,
        )

        compliance_data = data.get("compliance", {})
        compliance = ComplianceConfig(
            frameworks=[ComplianceFramework(f) for f in compliance_data.get("frameworks", [])],
            audit_log=compliance_data.get("audit_log", True),
        )

        deploy_data = data.get("deploy", {})
        resources_data = deploy_data.get("resources", {})
        deploy = DeployConfig(
            type=DeployType(deploy_data.get("type", "systemd")),
            replicas=deploy_data.get("replicas", 1),
            resources=ResourceConfig(
                memory=resources_data.get("memory", "256Mi"),
                cpu=resources_data.get("cpu", "100m"),
            ),
        )

        return cls(
            namespace=data["namespace"],
            version=data.get("version", "1.0"),
            node=node,
            storage=storage,
            capture=capture,
            ml=ml,
            alerts=alerts,
            compliance=compliance,
            deploy=deploy,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "version": self.version,
            "namespace": self.namespace,
            "node": {
                "id": self.node.id,
                "labels": self.node.labels,
            },
            "storage": {
                "base_dir": self.storage.base_dir,
                "out_dir": self.storage.out_dir,
                "cas_enabled": self.storage.cas_enabled,
                "retention_days": self.storage.retention_days,
            },
            "capture": {
                "window_seconds": self.capture.window_seconds,
                "privacy_mode": self.capture.privacy_mode.value,
                "watch_paths": self.capture.watch_paths,
                "watch_processes": self.capture.watch_processes,
                "exclude_paths": self.capture.exclude_paths,
            },
            "ml": {
                "enabled": self.ml.enabled,
                "threshold": self.ml.threshold,
                "models": [m.value for m in self.ml.models],
            },
            "alerts": {
                "enabled": self.alerts.enabled,
                "channels": [
                    {
                        "type": ch.type.value,
                        "url": ch.url,
                        "email": ch.email,
                        "severity": ch.severity.value,
                    }
                    for ch in self.alerts.channels
                ],
            },
            "compliance": {
                "frameworks": [f.value for f in self.compliance.frameworks],
                "audit_log": self.compliance.audit_log,
            },
            "deploy": {
                "type": self.deploy.type.value,
                "replicas": self.deploy.replicas,
                "resources": {
                    "memory": self.deploy.resources.memory,
                    "cpu": self.deploy.resources.cpu,
                },
            },
        }

    def to_yaml(self, path: Optional[str] = None) -> str:
        """Export configuration to YAML."""
        content = yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)
        if path:
            with open(path, "w") as f:
                f.write(content)
        return content

    def to_env(self) -> Dict[str, str]:
        """Export configuration as environment variables."""
        env = {
            "RITMA_NAMESPACE": self.namespace,
            "RITMA_BASE_DIR": self.storage.base_dir,
            "RITMA_CAS_ENABLE": "1" if self.storage.cas_enabled else "0",
            "RITMA_OUT_ENABLE": "1",
            "RITMA_WINDOW_SECONDS": str(self.capture.window_seconds),
            "RITMA_PRIVACY_MODE": self.capture.privacy_mode.value,
        }
        if self.node.id:
            env["RITMA_NODE_ID"] = self.node.id
        if self.storage.out_dir:
            env["RITMA_OUT_DIR"] = self.storage.out_dir
        return env

    def validate(self) -> bool:
        """Validate configuration."""
        errors = []
        
        if not self.namespace:
            errors.append("namespace is required")
        
        if self.capture.window_seconds < 10:
            errors.append("window_seconds must be >= 10")
        
        if self.ml.threshold < 0 or self.ml.threshold > 1:
            errors.append("ml.threshold must be between 0 and 1")
        
        if errors:
            raise ValueError(f"Invalid configuration: {', '.join(errors)}")
        
        return True
