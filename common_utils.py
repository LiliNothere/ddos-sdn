"""
Common utilities for DDoS Detection and Mitigation System.
Provides shared functionality across controller, ML, and mininet modules.
"""

import csv
import logging
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score

from config_loader import get_config, ensure_directories


# Initialize directories
ensure_directories()

# Configure logging
config = get_config()
logging.basicConfig(
    level=getattr(logging, config.logging.level),
    format=config.logging.format,
    handlers=[
        logging.FileHandler(config.logging.file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# CSV Headers - Updated to match ML service feature columns
FLOW_STATS_HEADER = [
    'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst',
    'ip_proto', 'icmp_code', 'icmp_type', 'flow_duration_sec', 'flow_duration_nsec',
    'idle_timeout', 'hard_timeout', 'flags', 'packet_count', 'byte_count',
    'packet_count_per_second', 'packet_count_per_nsecond',
    'byte_count_per_second', 'byte_count_per_nsecond', 'label'
]

PREDICT_FLOW_STATS_HEADER = [
    'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst',
    'ip_proto', 'icmp_code', 'icmp_type', 'flow_duration_sec', 'flow_duration_nsec',
    'idle_timeout', 'hard_timeout', 'flags', 'packet_count', 'byte_count',
    'packet_count_per_second', 'packet_count_per_nsecond',
    'byte_count_per_second', 'byte_count_per_nsecond'
]


@contextmanager
def safe_open(filepath: Path, mode: str = 'w', **kwargs) -> Generator:
    """Context manager for safe file operations with error handling."""
    try:
        with open(filepath, mode, newline='', encoding='utf-8', **kwargs) as f:
            yield f
    except IOError as e:
        logger.error(f"File operation failed for {filepath}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error with file {filepath}: {e}")
        raise


def init_csv_file(filepath: Path, header: List[str]) -> None:
    """Initialize a CSV file with header if it doesn't exist."""
    if not filepath.exists():
        with safe_open(filepath, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)
        logger.info(f"Initialized CSV file: {filepath}")


def append_csv_row(filepath: Path, row: List) -> None:
    """Append a row to a CSV file."""
    with safe_open(filepath, 'a') as f:
        writer = csv.writer(f)
        writer.writerow(row)


def clear_csv_file(filepath: Path, header: List[str]) -> None:
    """Clear a CSV file and write header."""
    with safe_open(filepath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(header)


def encode_ip(ip_str: str) -> Tuple[int, int]:
    """Encode IP address into two numeric features: (network_part, host_part)"""
    try:
        parts = ip_str.split('.')
        if len(parts) == 4:
            # Use first 3 octets as network, last as host
            network = int(parts[0]) * 256 * 256 + int(parts[1]) * 256 + int(parts[2])
            host = int(parts[3])
            return network, host
    except (ValueError, AttributeError):
        pass
    return 0, 0


def preprocess_flow_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Preprocess flow data by encoding IP address columns.
    Replaces IP columns with network_part and host_part features.
    """
    df = df.copy()
    # Columns for IP addresses
    ip_columns = ['ip_src', 'ip_dst']

    for ip_col in ip_columns:
        if ip_col in df.columns:
            encoded = df[ip_col].apply(encode_ip)
            df[f'{ip_col}_network'] = encoded.apply(lambda x: x[0])
            df[f'{ip_col}_host'] = encoded.apply(lambda x: x[1])
            # Drop original IP column
            df = df.drop(columns=[ip_col])

    return df


def load_and_preprocess_data(filepath: Path) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load and preprocess flow data from CSV.
    Returns (X, y) arrays ready for ML training.
    """
    try:
        df = pd.read_csv(filepath, encoding='utf-8')
    except FileNotFoundError:
        logger.error(f"Data file not found: {filepath}")
        raise
    except pd.errors.EmptyDataError:
        logger.error(f"Data file is empty: {filepath}")
        raise

    df = preprocess_flow_data(df)

    # Features: all columns except last (label) and flow_id
    feature_cols = [c for c in df.columns if c not in ['label', 'flow_id']]
    X = df[feature_cols].values
    X = X.astype('float64')

    # Labels: last column
    y = df['label'].values

    return X, y


def split_data(X: np.ndarray, y: np.ndarray,
               test_size: float = 0.25,
               random_state: int = 42) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Split data into train/test sets."""
    return train_test_split(X, y, test_size=test_size, random_state=random_state)


def train_model(classifier, X_train: np.ndarray, y_train: np.ndarray):
    """Train a classifier and return the fitted model."""
    return classifier.fit(X_train, y_train)


def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    """
    Evaluate model performance.
    Returns dictionary with confusion matrix, accuracy, and other metrics.
    """
    y_pred = model.predict(X_test)

    cm = confusion_matrix(y_test, y_pred)
    acc = accuracy_score(y_test, y_pred)

    return {
        'confusion_matrix': cm,
        'accuracy': acc,
        'error_rate': 1.0 - acc,
        'predictions': y_pred,
        'true_labels': y_test
    }


def log_model_results(model_name: str, results: dict) -> None:
    """Log model evaluation results."""
    cm = results['confusion_matrix']
    acc = results['accuracy']
    error_rate = results['error_rate']

    logger.info(f"{'='*78}")
    logger.info(f"{model_name} Results")
    logger.info(f"{'='*78}")
    logger.info(f"Confusion Matrix:\n{cm}")
    logger.info(f"Success Accuracy = {acc*100:.2f}%")
    logger.info(f"Fail Accuracy = {error_rate*100:.2f}%")
    logger.info(f"{'='*78}")


def calculate_flow_features(stat) -> dict:
    """
    Calculate flow features from OpenFlow stats.
    Returns dictionary of computed features.
    """
    features = {}

    try:
        features['packet_count_per_second'] = stat.packet_count / stat.duration_sec
    except (ZeroDivisionError, AttributeError):
        features['packet_count_per_second'] = 0

    try:
        features['packet_count_per_nsecond'] = stat.packet_count / stat.duration_nsec
    except (ZeroDivisionError, AttributeError):
        features['packet_count_per_nsecond'] = 0

    try:
        features['byte_count_per_second'] = stat.byte_count / stat.duration_sec
    except (ZeroDivisionError, AttributeError):
        features['byte_count_per_second'] = 0

    try:
        features['byte_count_per_nsecond'] = stat.byte_count / stat.duration_nsec
    except (ZeroDivisionError, AttributeError):
        features['byte_count_per_nsecond'] = 0

    return features


def extract_flow_info(stat) -> dict:
    """
    Extract flow information from OpenFlow flow stats.
    Returns dictionary with flow identifiers and protocol-specific info.
    """
    info = {
        'ip_src': stat.match.get('ipv4_src', '0.0.0.0'),
        'ip_dst': stat.match.get('ipv4_dst', '0.0.0.0'),
        'ip_proto': stat.match.get('ip_proto', 0),
        'icmp_code': -1,
        'icmp_type': -1,
        'tp_src': 0,
        'tp_dst': 0,
    }

    ip_proto = info['ip_proto']

    if ip_proto == 1:  # ICMP
        info['icmp_code'] = stat.match.get('icmpv4_code', -1)
        info['icmp_type'] = stat.match.get('icmpv4_type', -1)
    elif ip_proto == 6:  # TCP
        info['tp_src'] = stat.match.get('tcp_src', 0)
        info['tp_dst'] = stat.match.get('tcp_dst', 0)
    elif ip_proto == 17:  # UDP
        info['tp_src'] = stat.match.get('udp_src', 0)
        info['tp_dst'] = stat.match.get('udp_dst', 0)

    # Create flow ID
    info['flow_id'] = (f"{info['ip_src']}{info['tp_src']}"
                       f"{info['ip_dst']}{info['tp_dst']}{info['ip_proto']}")

    return info


def create_flow_csv_row(timestamp: float, datapath_id: int, flow_info: dict,
                        stat, features: dict, label: Optional[int] = None) -> List:
    """
    Create a CSV row for flow statistics.
    """
    row = [
        timestamp,
        datapath_id,
        flow_info['flow_id'],
        flow_info['ip_src'],
        flow_info['tp_src'],
        flow_info['ip_dst'],
        flow_info['tp_dst'],
        flow_info['ip_proto'],
        flow_info['icmp_code'],
        flow_info['icmp_type'],
        stat.duration_sec,
        stat.duration_nsec,
        stat.idle_timeout,
        stat.hard_timeout,
        stat.flags,
        stat.packet_count,
        stat.byte_count,
        features['packet_count_per_second'],
        features['packet_count_per_nsecond'],
        features['byte_count_per_second'],
        features['byte_count_per_nsecond'],
    ]

    if label is not None:
        row.append(label)

    return row


def setup_matplotlib_style() -> None:
    """Configure matplotlib style for compatibility across versions."""
    import matplotlib.pyplot as plt

    # Try modern seaborn styles first, fallback to built-in styles
    style_options = [
        'seaborn-v0_8-darkgrid',
        'seaborn-v0_8-whitegrid',
        'seaborn-darkgrid',
        'seaborn-whitegrid',
        'ggplot',
        'classic'
    ]

    for style in style_options:
        try:
            plt.style.use(style)
            logger.debug(f"Using matplotlib style: {style}")
            return
        except OSError:
            continue

    # If no style works, use default
    logger.warning("No preferred matplotlib style available, using default")


def get_timestamp() -> float:
    """Get current timestamp."""
    return datetime.now().timestamp()


class FlowDataCollector:
    """Collects and manages flow statistics data."""

    def __init__(self, stats_file: Path, label: int = 0):
        self.stats_file = stats_file
        self.label = label
        init_csv_file(stats_file, FLOW_STATS_HEADER)

    def collect(self, ev, datapath_id: int) -> None:
        """Collect flow stats from OpenFlow event."""
        timestamp = get_timestamp()
        body = ev.msg.body

        # Filter priority 1 flows and sort
        flows = sorted(
            [flow for flow in body if flow.priority == 1],
            key=lambda f: (f.match.get('eth_type', 0),
                          f.match.get('ipv4_src', ''),
                          f.match.get('ipv4_dst', ''),
                          f.match.get('ip_proto', 0))
        )

        rows = []
        for stat in flows:
            flow_info = extract_flow_info(stat)
            features = calculate_flow_features(stat)
            row = create_flow_csv_row(
                timestamp, datapath_id, flow_info, stat, features, self.label
            )
            rows.append(row)

        # Write all rows at once
        if rows:
            with safe_open(self.stats_file, 'a') as f:
                writer = csv.writer(f)
                writer.writerows(rows)

            logger.debug(f"Collected {len(rows)} flow records")


class FlowPredictor:
    """Handles flow prediction using trained ML model."""

    def __init__(self, model, predict_file: Path, threshold: float = 80.0):
        self.model = model
        self.predict_file = predict_file
        self.threshold = threshold
        init_csv_file(predict_file, PREDICT_FLOW_STATS_HEADER)

    def predict(self, ev, datapath_id: int) -> dict:
        """Predict flow labels and detect anomalies."""
        timestamp = get_timestamp()
        body = ev.msg.body

        # Collect prediction data
        flows = sorted(
            [flow for flow in body if flow.priority == 1],
            key=lambda f: (f.match.get('eth_type', 0),
                          f.match.get('ipv4_src', ''),
                          f.match.get('ipv4_dst', ''),
                          f.match.get('ip_proto', 0))
        )

        rows = []
        flow_infos = []

        for stat in flows:
            flow_info = extract_flow_info(stat)
            features = calculate_flow_features(stat)
            row = create_flow_csv_row(timestamp, datapath_id, flow_info, stat, features)
            rows.append(row)
            flow_infos.append(flow_info)

        if not rows:
            return {'legitimate': 0, 'ddos': 0, 'victim': None, 'is_attack': False}

        # Write prediction data
        with safe_open(self.predict_file, 'a') as f:
            writer = csv.writer(f)
            writer.writerows(rows)

        # Load and preprocess for prediction
        try:
            predict_df = pd.read_csv(self.predict_file, encoding='utf-8')
            predict_df = preprocess_flow_data(predict_df)
            # Drop flow_id column if present
            if 'flow_id' in predict_df.columns:
                predict_df = predict_df.drop(columns=['flow_id'])
            X_predict = predict_df.values.astype('float64')

            # Predict
            y_pred = self.model.predict(X_predict)

            # Count legitimate vs DDoS
            legitimate = int(np.sum(y_pred == 0))
            ddos = int(np.sum(y_pred == 1))
            total = len(y_pred)

            # Determine victim if attack detected
            victim = None
            is_attack = False

            if ddos > 0 and (legitimate / total * 100) <= self.threshold:
                is_attack = True
                # Find first DDoS flow's destination
                for i, pred in enumerate(y_pred):
                    if pred == 1:
                        # Extract victim from ip_dst (need to find correct column after preprocessing)
                        victim_ip = predict_df.iloc[i].get('ip_dst_host', 1)
                        try:
                            victim = int(victim_ip) % 20
                        except (ValueError, TypeError):
                            victim = 1
                        break

            # Clear prediction file for next round
            clear_csv_file(self.predict_file, PREDICT_FLOW_STATS_HEADER)

            return {
                'legitimate': legitimate,
                'ddos': ddos,
                'total': total,
                'victim': victim,
                'is_attack': is_attack,
                'legitimate_pct': legitimate / total * 100 if total > 0 else 100
            }

        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            clear_csv_file(self.predict_file, PREDICT_FLOW_STATS_HEADER)
            return {'legitimate': 0, 'ddos': 0, 'victim': None, 'is_attack': False}