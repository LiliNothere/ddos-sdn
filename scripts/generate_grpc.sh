#!/bin/bash
# Generate gRPC Python code from protobuf definition

set -e

cd "$(dirname "$0")/../ml_service"

echo "Generating gRPC code from ddos.proto..."

python -m grpc_tools.protoc \
    --proto_path=. \
    --python_out=. \
    --grpc_python_out=. \
    ddos.proto

echo "Generated files:"
ls -la *_pb2*.py

echo "Done!"