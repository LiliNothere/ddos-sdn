"""
ML Service Package for DDoS Detection
"""

from .config import settings, MODEL_PARAMS, FEATURE_COLUMNS, TARGET_COLUMN
from .model import DDoSModel, ModelManager
from .faucet_client import FaucetClient, FlowStat, PortStat, FaucetConfigManager
from .grpc_service import DDoSServiceServicer
from .server import app

__all__ = [
    "settings",
    "MODEL_PARAMS",
    "FEATURE_COLUMNS",
    "TARGET_COLUMN",
    "DDoSModel",
    "ModelManager",
    "FaucetClient",
    "FlowStat",
    "PortStat",
    "FaucetConfigManager",
    "DDoSServiceServicer",
    "app",
]

__version__ = "1.0.0"