"""
ML Service Configuration
Uses config_loader for consistency with rest of application
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from functools import lru_cache

from config_loader import get_config


class Settings(BaseSettings):
    # Service settings
    service_host: str = "0.0.0.0"
    service_port: int = 8080
    grpc_port: int = 50051
    log_level: str = "INFO"

    # Model settings
    model_dir: str = "./models"
    default_model: str = "RandomForest"
    model_version: str = "1.0.0"

    # Training settings
    dataset_path: str = "./data/FlowStatsfile.csv"
    test_size: float = 0.25
    random_state: int = 42

    # Detection settings
    stats_poll_interval: int = 10  # seconds
    ddos_threshold_percent: float = 20.0  # Alert if >20% DDoS
    legitimate_threshold_percent: float = 80.0

    # Faucet integration
    faucet_host: str = "localhost"
    faucet_rest_port: int = 9302
    gauge_prometheus_port: int = 9303
    faucet_acl_name: str = "block-malicious"
    # Ports >= this value are considered trunk/inter-switch ports and won't be blocked
    faucet_trunk_port_threshold: int = 4

    # Mitigation settings
    mitigation_duration: int = 120  # seconds
    mitigation_cooldown: int = 300  # seconds between mitigations

    # Prometheus metrics
    metrics_enabled: bool = True
    metrics_port: int = 9090

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get settings, loading from config_loader first, then env overrides"""
    config = get_config()
    ml_config = config.ml_service

    # Create settings with config_loader values as defaults
    settings = Settings(
        service_host=ml_config.service_host,
        service_port=ml_config.service_port,
        grpc_port=ml_config.grpc_port,
        log_level=ml_config.log_level,
        model_dir=str(ml_config.model_dir),
        default_model=ml_config.default_model,
        model_version=ml_config.model_version,
        dataset_path=str(ml_config.dataset_path),
        test_size=config.training.test_size,
        random_state=config.training.random_state,
        stats_poll_interval=ml_config.stats_poll_interval,
        ddos_threshold_percent=ml_config.ddos_threshold_percent,
        legitimate_threshold_percent=ml_config.legitimate_threshold_percent,
        faucet_host=ml_config.faucet_host,
        faucet_rest_port=ml_config.faucet_rest_port,
        gauge_prometheus_port=ml_config.gauge_prometheus_port,
        faucet_acl_name=ml_config.faucet_acl_name,
        faucet_trunk_port_threshold=getattr(ml_config, 'faucet_trunk_port_threshold', 4),
        mitigation_duration=ml_config.mitigation_duration,
        mitigation_cooldown=ml_config.mitigation_cooldown,
        metrics_enabled=ml_config.metrics_enabled,
        metrics_port=ml_config.metrics_port,
    )
    return settings


# Global settings instance
settings = get_settings()

# Model parameters for different algorithms
MODEL_PARAMS = {
    "RandomForest": {
        "n_estimators": 100,
        "criterion": "entropy",
        "max_depth": 10,
        "min_samples_split": 5,
        "min_samples_leaf": 2,
        "random_state": 42,
        "n_jobs": -1
    },
    "KNN": {
        "n_neighbors": 5,
        "metric": "minkowski",
        "p": 2,
        "weights": "distance"
    },
    "DecisionTree": {
        "criterion": "entropy",
        "max_depth": 10,
        "min_samples_split": 5,
        "min_samples_leaf": 2,
        "random_state": 42
    },
    "LogisticRegression": {
        "solver": "liblinear",
        "C": 1.0,
        "max_iter": 1000,
        "random_state": 42
    },
    "NaiveBayes": {
        "var_smoothing": 1e-9
    },
    "SVM": {
        "kernel": "rbf",
        "C": 1.0,
        "gamma": "scale",
        "random_state": 42,
        "probability": True
    }
}

# Feature columns (must match training data) - IP columns removed to prevent data leakage
FEATURE_COLUMNS = [
    'timestamp', 'datapath_id', 'flow_id', 'tp_src',
    'tp_dst', 'ip_proto', 'icmp_code', 'icmp_type',
    'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout',
    'hard_timeout', 'flags', 'packet_count', 'byte_count',
    'packet_count_per_second', 'packet_count_per_nsecond',
    'byte_count_per_second', 'byte_count_per_nsecond'
]

# Target column
TARGET_COLUMN = 'label'  # 0 = benign, 1 = ddos

# Numeric features used by model (excludes flow_id, ip_src, ip_dst)
NUMERIC_FEATURE_COLUMNS = [
    'timestamp', 'datapath_id', 'tp_src',
    'tp_dst', 'ip_proto', 'icmp_code', 'icmp_type',
    'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout',
    'hard_timeout', 'flags', 'packet_count', 'byte_count',
    'packet_count_per_second', 'packet_count_per_nsecond',
    'byte_count_per_second', 'byte_count_per_nsecond'
]