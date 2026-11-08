# ML Service Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY ml_service/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Install grpc tools for proto compilation
RUN pip install --no-cache-dir grpcio-tools

# Copy source code
COPY ml_service /app/ml_service
COPY integration /app/integration
COPY config.ini /app/config.ini
COPY config_loader.py /app/config_loader.py
COPY common_utils.py /app/common_utils.py

# Create directories
RUN mkdir -p /app/models /app/data /var/log/ml-service /var/log/ml-bridge /etc/faucet/acls

# Generate gRPC code from proto file
RUN cd /app/ml_service && python -m grpc_tools.protoc \
    --proto_path=. \
    --python_out=. \
    --grpc_python_out=. \
    ddos.proto

# Fix generated imports (change from ml_service.proto to relative)
RUN sed -i 's/import ddos_pb2 as ddos__pb2/from . import ddos_pb2 as ddos__pb2/' /app/ml_service/ddos_pb2_grpc.py 2>/dev/null || true
RUN sed -i 's/import ddos_pb2/from . import ddos_pb2/' /app/ml_service/ddos_pb2_grpc.py 2>/dev/null || true

# Set Python path
ENV PYTHONPATH=/app:/app/ml_service:/app/integration

# Default command
CMD ["python", "-m", "ml_service.server"]