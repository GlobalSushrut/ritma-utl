"""Ritma client for deployment and management."""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Dict, List

from .config import RitmaConfig


class RitmaClient:
    """Client for deploying and managing Ritma."""

    def __init__(self, config: RitmaConfig):
        self.config = config
        self._ritma_bin = self._find_ritma()

    def _find_ritma(self) -> str:
        """Find ritma binary."""
        paths = [
            "/usr/bin/ritma",
            "/usr/local/bin/ritma",
            shutil.which("ritma"),
        ]
        for p in paths:
            if p and os.path.isfile(p):
                return p
        raise RuntimeError("ritma binary not found. Install with: sudo apt install ritma")

    def deploy(self) -> bool:
        """Deploy Ritma with current configuration."""
        self.config.validate()
        
        deploy_type = self.config.deploy.type.value
        
        if deploy_type == "systemd":
            return self._deploy_systemd()
        elif deploy_type == "kubernetes":
            return self._deploy_kubernetes()
        elif deploy_type == "docker":
            return self._deploy_docker()
        else:
            return self._deploy_standalone()

    def _deploy_systemd(self) -> bool:
        """Deploy as systemd service."""
        # Write config file
        config_path = Path("/etc/ritma/ritma.yaml")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config.to_yaml(str(config_path))
        
        # Write environment file
        env_path = Path("/etc/ritma/ritma.conf")
        with open(env_path, "w") as f:
            for key, value in self.config.to_env().items():
                f.write(f"{key}={value}\n")
        
        # Reload and start service
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "ritma-sidecar"], check=True)
        subprocess.run(["systemctl", "start", "ritma-sidecar"], check=True)
        
        return True

    def _deploy_kubernetes(self) -> str:
        """Generate Kubernetes manifests."""
        manifest = f"""---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ritma-config
  namespace: {self.config.namespace}
data:
  ritma.yaml: |
{self._indent_yaml(self.config.to_yaml(), 4)}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ritma-sidecar
  namespace: {self.config.namespace}
spec:
  selector:
    matchLabels:
      app: ritma-sidecar
  template:
    metadata:
      labels:
        app: ritma-sidecar
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: ritma-sidecar
        image: ritma/sidecar:latest
        securityContext:
          privileged: true
        resources:
          requests:
            memory: "{self.config.deploy.resources.memory}"
            cpu: "{self.config.deploy.resources.cpu}"
        volumeMounts:
        - name: config
          mountPath: /etc/ritma
        - name: data
          mountPath: /var/lib/ritma
        - name: host-root
          mountPath: /host
          readOnly: true
        env:
        - name: RITMA_NAMESPACE
          value: "{self.config.namespace}"
        - name: RITMA_NODE_ID
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
      volumes:
      - name: config
        configMap:
          name: ritma-config
      - name: data
        hostPath:
          path: /var/lib/ritma
          type: DirectoryOrCreate
      - name: host-root
        hostPath:
          path: /
          type: Directory
"""
        return manifest

    def _deploy_docker(self) -> str:
        """Generate Docker Compose file."""
        compose = f"""version: '3.8'
services:
  ritma-sidecar:
    image: ritma/sidecar:latest
    container_name: ritma-sidecar
    restart: unless-stopped
    privileged: true
    pid: host
    network_mode: host
    volumes:
      - ./ritma.yaml:/etc/ritma/ritma.yaml:ro
      - ritma-data:/var/lib/ritma
      - /:/host:ro
    environment:
      - RITMA_NAMESPACE={self.config.namespace}
      - RITMA_BASE_DIR=/var/lib/ritma
      - RITMA_OUT_ENABLE=1
      - RITMA_CAS_ENABLE=1

volumes:
  ritma-data:
"""
        return compose

    def _deploy_standalone(self) -> bool:
        """Deploy standalone with config file."""
        config_path = Path(self.config.storage.base_dir) / "ritma.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config.to_yaml(str(config_path))
        
        env = self.config.to_env()
        env_str = " ".join(f"{k}={v}" for k, v in env.items())
        
        print(f"Config written to: {config_path}")
        print(f"Run with: {env_str} ritma-sidecar")
        return True

    def _indent_yaml(self, yaml_str: str, spaces: int) -> str:
        """Indent YAML string."""
        indent = " " * spaces
        return "\n".join(indent + line for line in yaml_str.split("\n"))

    def status(self) -> Dict:
        """Get Ritma service status."""
        result = subprocess.run(
            ["systemctl", "is-active", "ritma-sidecar"],
            capture_output=True,
            text=True,
        )
        return {
            "active": result.stdout.strip() == "active",
            "namespace": self.config.namespace,
        }

    def capture(self, duration: int = 60, output: Optional[str] = None) -> str:
        """Run a capture session."""
        cmd = [self._ritma_bin, "capture", "--duration", str(duration)]
        if output:
            cmd.extend(["--output", output])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

    def verify(self, proofpack_path: str) -> bool:
        """Verify a proofpack."""
        result = subprocess.run(
            [self._ritma_bin, "verify", proofpack_path],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def export(self, output: str, namespace: Optional[str] = None) -> str:
        """Export sealed windows."""
        cmd = [self._ritma_bin, "export-window", "--output", output]
        if namespace:
            cmd.extend(["--namespace", namespace])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
