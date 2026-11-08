"""
Configuration loader for DDoS Detection and Mitigation System.
Supports loading from config.ini with environment variable overrides.
"""

import os
import configparser
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass


@dataclass
class ControllerConfig:
    ip: str
    port: int
    of_protocol_version: str


@dataclass
class NetworkConfig:
    num_switches: int
    hosts_per_switch: int
    base_ip: str
    switch_protocol: str


@dataclass
class PathsConfig:
    data_dir: Path
    flow_stats_file: Path
    predict_flow_stats_file: Path
    dataset_file: Path
    webserver_dir: Path
    downloads_dir: Path


@dataclass
class TrainingConfig:
    test_size: float
    random_state: int
    n_estimators: int
    criterion: str


@dataclass
class DetectionConfig:
    stats_request_interval: int
    legitimate_traffic_threshold: float


@dataclass
class MitigationConfig:
    block_duration: int
    flow_priority_mitigation: int
    flow_priority_normal: int


@dataclass
class LoggingConfig:
    level: str
    format: str
    file: Path


@dataclass
class TrafficGenerationConfig:
    benign_iterations: int
    benign_requests_per_iteration: int
    ddos_attack_duration: int
    ddos_sleep_between_attacks: int


@dataclass
class MLServiceConfig:
    service_host: str
    service_port: int
    grpc_port: int
    log_level: str
    model_dir: Path
    default_model: str
    model_version: str
    dataset_path: Path
    stats_poll_interval: int
    ddos_threshold_percent: float
    legitimate_threshold_percent: float
    faucet_host: str
    faucet_rest_port: int
    gauge_prometheus_port: int
    faucet_acl_name: str
    mitigation_duration: int
    mitigation_cooldown: int
    metrics_enabled: bool
    metrics_port: int


@dataclass
class AppConfig:
    controller: ControllerConfig
    network: NetworkConfig
    paths: PathsConfig
    training: TrainingConfig
    detection: DetectionConfig
    mitigation: MitigationConfig
    logging: LoggingConfig
    traffic_generation: TrafficGenerationConfig
    ml_service: MLServiceConfig


class ConfigLoader:
    """Loads and manages application configuration."""

    _instance: Optional['ConfigLoader'] = None
    _config: Optional[AppConfig] = None

    def __new__(cls) -> 'ConfigLoader':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._config is None:
            self._config = self._load_config()

    def _load_config(self) -> AppConfig:
        """Load configuration from config.ini with environment variable overrides."""
        config_path = Path(__file__).parent / 'config.ini'

        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        parser = configparser.RawConfigParser()
        parser.read(config_path)

        # Helper to get value with env override
        def get_value(section: str, key: str, fallback: Any = None) -> str:
            env_key = f"DDOS_{section.upper()}_{key.upper()}"
            return os.environ.get(env_key, parser.get(section, key, fallback=fallback))

        def get_int(section: str, key: str, fallback: int = 0) -> int:
            return int(get_value(section, key, str(fallback)))

        def get_float(section: str, key: str, fallback: float = 0.0) -> float:
            return float(get_value(section, key, str(fallback)))

        def get_bool(section: str, key: str, fallback: bool = False) -> bool:
            val = get_value(section, key, str(fallback)).lower()
            return val in ('true', '1', 'yes', 'on')

        def get_path(section: str, key: str) -> Path:
            return Path(get_value(section, key)).expanduser().resolve()

        # Parse configurations
        controller = ControllerConfig(
            ip=get_value('controller', 'controller_ip'),
            port=get_int('controller', 'controller_port'),
            of_protocol_version=get_value('controller', 'of_protocol_version'),
        )

        network = NetworkConfig(
            num_switches=get_int('network', 'num_switches'),
            hosts_per_switch=get_int('network', 'hosts_per_switch'),
            base_ip=get_value('network', 'base_ip'),
            switch_protocol=get_value('network', 'switch_protocol'),
        )

        paths = PathsConfig(
            data_dir=get_path('paths', 'data_dir'),
            flow_stats_file=get_path('paths', 'flow_stats_file'),
            predict_flow_stats_file=get_path('paths', 'predict_flow_stats_file'),
            dataset_file=get_path('paths', 'dataset_file'),
            webserver_dir=get_path('paths', 'webserver_dir'),
            downloads_dir=get_path('paths', 'downloads_dir'),
        )

        training = TrainingConfig(
            test_size=get_float('training', 'test_size'),
            random_state=get_int('training', 'random_state'),
            n_estimators=get_int('training', 'n_estimators'),
            criterion=get_value('training', 'criterion'),
        )

        detection = DetectionConfig(
            stats_request_interval=get_int('detection', 'stats_request_interval'),
            legitimate_traffic_threshold=get_float('detection', 'legitimate_traffic_threshold'),
        )

        mitigation = MitigationConfig(
            block_duration=get_int('mitigation', 'block_duration'),
            flow_priority_mitigation=get_int('mitigation', 'flow_priority_mitigation'),
            flow_priority_normal=get_int('mitigation', 'flow_priority_normal'),
        )

        logging = LoggingConfig(
            level=get_value('logging', 'level'),
            format=get_value('logging', 'format'),
            file=get_path('logging', 'file'),
        )

        traffic_generation = TrafficGenerationConfig(
            benign_iterations=get_int('traffic_generation', 'benign_iterations'),
            benign_requests_per_iteration=get_int('traffic_generation', 'benign_requests_per_iteration'),
            ddos_attack_duration=get_int('traffic_generation', 'ddos_attack_duration'),
            ddos_sleep_between_attacks=get_int('traffic_generation', 'ddos_sleep_between_attacks'),
        )

        ml_service = MLServiceConfig(
            service_host=get_value('ml_service', 'service_host'),
            service_port=get_int('ml_service', 'service_port'),
            grpc_port=get_int('ml_service', 'grpc_port'),
            log_level=get_value('ml_service', 'log_level'),
            model_dir=get_path('ml_service', 'model_dir'),
            default_model=get_value('ml_service', 'default_model'),
            model_version=get_value('ml_service', 'model_version'),
            dataset_path=get_path('ml_service', 'dataset_path'),
            stats_poll_interval=get_int('ml_service', 'stats_poll_interval'),
            ddos_threshold_percent=get_float('ml_service', 'ddos_threshold_percent'),
            legitimate_threshold_percent=get_float('ml_service', 'legitimate_threshold_percent'),
            faucet_host=get_value('ml_service', 'faucet_host'),
            faucet_rest_port=get_int('ml_service', 'faucet_rest_port'),
            gauge_prometheus_port=get_int('ml_service', 'gauge_prometheus_port'),
            faucet_acl_name=get_value('ml_service', 'faucet_acl_name'),
            mitigation_duration=get_int('ml_service', 'mitigation_duration'),
            mitigation_cooldown=get_int('ml_service', 'mitigation_cooldown'),
            metrics_enabled=get_bool('ml_service', 'metrics_enabled'),
            metrics_port=get_int('ml_service', 'metrics_port'),
        )

        return AppConfig(
            controller=controller,
            network=network,
            paths=paths,
            training=training,
            detection=detection,
            mitigation=mitigation,
            logging=logging,
            traffic_generation=traffic_generation,
            ml_service=ml_service,
        )

    @property
    def config(self) -> AppConfig:
        """Get the loaded configuration."""
        if self._config is None:
            self._config = self._load_config()
        return self._config

    def reload(self) -> None:
        """Reload configuration from file."""
        self._config = self._load_config()


def get_config() -> AppConfig:
    """Convenience function to get the global configuration."""
    return ConfigLoader().config


def ensure_directories() -> None:
    """Ensure all required directories exist."""
    config = get_config()
    config.paths.data_dir.mkdir(parents=True, exist_ok=True)
    config.paths.webserver_dir.mkdir(parents=True, exist_ok=True)
    config.paths.downloads_dir.mkdir(parents=True, exist_ok=True)
    config.logging.file.parent.mkdir(parents=True, exist_ok=True)
    config.ml_service.model_dir.mkdir(parents=True, exist_ok=True)