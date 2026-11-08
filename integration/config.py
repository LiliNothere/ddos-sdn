"""
Integration Configuration
Re-exports ML service configuration for use in integration layer
"""
import sys
from pathlib import Path

# Add ml_service to path
sys.path.insert(0, str(Path(__file__).parent.parent / "ml_service"))

from ml_service.config import settings, MODEL_PARAMS, FEATURE_COLUMNS, TARGET_COLUMN, IP_COLUMNS

__all__ = [
    "settings",
    "MODEL_PARAMS",
    "FEATURE_COLUMNS",
    "TARGET_COLUMN",
    "IP_COLUMNS",
]