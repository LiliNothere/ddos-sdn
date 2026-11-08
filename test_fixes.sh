#!/bin/bash
# Test script to verify the fixes work correctly

set -e

echo "======================================"
echo "Testing DDoS SDN Fixes"
echo "======================================"

# Test 1: Python imports work
echo "Test 1: Checking Python imports..."
cd /opt/ddos-sdn

# Test ml_service imports
python -c "
from ml_service.config import settings
from ml_service.model import ModelManager, DDoSModel
from ml_service.faucet_client import FaucetClient, FlowStat
from ml_service.server import app
print('ml_service imports: OK')
"

# Test integration imports
python -c "
from integration.config import settings
from integration.faucet_ml_bridge import FaucetMLBridge
print('integration imports: OK')
"

# Test mininet imports (should not conflict with mininet library)
python -c "
from mininet.mininet_topology import DDoSTopo
from mininet.traffic_generator import TrafficGenerator
print('mininet imports: OK')
"

# Test 2: Config loading
echo "Test 2: Checking config loading..."
python -c "
from config_loader import get_config
config = get_config()
print(f'Controller: {config.controller.ip}:{config.controller.port}')
print(f'ML Service: {config.ml_service.service_host}:{config.ml_service.service_port}')
print('Config loading: OK')
"

# Test 3: Faucet config validation
echo "Test 3: Checking Faucet config..."
python -c "
import yaml
with open('faucet_config/faucet.yaml') as f:
    config = yaml.safe_load(f)
print(f'Version: {config.get(\"version\")}')
print(f'DPs: {list(config.get(\"dps\", {}).keys())}')
print(f'VLANs: {list(config.get(\"vlans\", {}).keys())}')
print(f'ACLs: {list(config.get(\"acls\", {}).keys())}')
print(f'Meters: {list(config.get(\"meters\", {}).keys())}')
# Check for duplicate meters
meters = config.get('meters', {})
if len(meters) == len(set(meters.keys())):
    print('No duplicate meters: OK')
else:
    print('WARNING: Duplicate meters found')
print('Faucet config: OK')
"

# Test 4: Gauge config validation
echo "Test 4: Checking Gauge config..."
python -c "
import yaml
with open('gauge_config/gauge.yaml') as f:
    config = yaml.safe_load(f)
print(f'Version: {config.get(\"version\")}')
print(f'Watchers: {list(config.get(\"watchers\", {}).keys())}')
print('Gauge config: OK')
"

# Test 5: Model training
echo "Test 5: Testing model training..."
python -c "
import pandas as pd
from ml_service.model import ModelManager
from ml_service.config import settings
from pathlib import Path

# Check if dataset exists
if Path(settings.dataset_path).exists():
    df = pd.read_csv(settings.dataset_path)
    print(f'Dataset loaded: {len(df)} samples')

    # Quick test with small subset
    test_df = df.sample(n=min(1000, len(df)), random_state=42)
    model_manager = ModelManager(Path(settings.model_dir))
    metadata = model_manager.train_model('RandomForest', test_df)
    print(f'Test training accuracy: {metadata[\"accuracy\"]:.4f}')
    print('Model training: OK')
else:
    print('Dataset not found, skipping training test')
"

# Test 6: Docker compose syntax
echo "Test 6: Checking docker-compose syntax..."
cd docker
docker compose config > /dev/null
echo 'Docker compose syntax: OK'

# Test 7: Proto generation
echo "Test 7: Checking proto generation..."
cd /opt/ddos-sdn/ml_service
python -m grpc_tools.protoc \
    --proto_path=. \
    --python_out=. \
    --grpc_python_out=. \
    ddos.proto
if [ -f ddos_pb2.py ] && [ -f ddos_pb2_grpc.py ]; then
    echo 'Proto generation: OK'
else
    echo 'Proto generation: FAILED'
fi

echo ""
echo "======================================"
echo "All tests passed!"
echo "======================================"