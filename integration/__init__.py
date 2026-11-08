"""
Integration Package for DDoS Detection System
Connects Faucet/Gauge -> ML Service -> Faucet Mitigation
"""

from .config import settings, MODEL_PARAMS, FEATURE_COLUMNS, TARGET_COLUMN, IP_COLUMNS
from .faucet_ml_bridge import FaucetMLBridge, SwitchState

__all__ = [
    "settings",
    "MODEL_PARAMS",
    "FEATURE_COLUMNS",
    "TARGET_COLUMN",
    "IP_COLUMNS",
    "FaucetMLBridge",
    "SwitchState",
]

__version__ = "1.0.0"