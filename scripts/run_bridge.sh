#!/bin/bash
# Run ML Bridge (Gauge -> ML -> Faucet)

set -e

cd "$(dirname "$0")/.."

# Activate virtual environment if exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Set Python path
export PYTHONPATH="$(pwd):$(pwd)/ml_service:$(pwd)/integration:$PYTHONPATH"

# Generate gRPC code if needed
if [ ! -f "ml_service/ddos_pb2.py" ]; then
    echo "Generating gRPC code..."
    python -m grpc_tools.protoc \
        --proto_path=ml_service \
        --python_out=ml_service \
        --grpc_python_out=ml_service \
        ml_service/ddos.proto
fi

# Run bridge
echo "Starting ML Bridge..."
python -m integration.faucet_ml_bridge