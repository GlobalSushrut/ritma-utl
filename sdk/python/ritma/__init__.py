"""
Ritma SDK for Python
Court-grade forensic security observability platform

Usage:
    from ritma import RitmaConfig, RitmaClient
    
    # Load config
    config = RitmaConfig.from_yaml("ritma.yaml")
    
    # Deploy
    client = RitmaClient(config)
    client.deploy()
"""

from .config import RitmaConfig
from .client import RitmaClient
from .models import (
    NodeConfig,
    StorageConfig,
    CaptureConfig,
    MLConfig,
    AlertConfig,
    ComplianceConfig,
    DeployConfig,
)

__version__ = "0.1.0"
__all__ = [
    "RitmaConfig",
    "RitmaClient",
    "NodeConfig",
    "StorageConfig", 
    "CaptureConfig",
    "MLConfig",
    "AlertConfig",
    "ComplianceConfig",
    "DeployConfig",
]
