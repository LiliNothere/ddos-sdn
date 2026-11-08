#!/bin/bash
# Ubuntu VM Deployment Script for DDoS SDN Detection & Mitigation
# Run with: sudo bash deploy/install_ubuntu.sh
# Tested on Ubuntu 24.04 LTS

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

# Configuration
PROJECT_DIR="/opt/ddos-sdn"
# Update this to your actual repository URL
REPO_URL="https://github.com/your-org/ddos-sdn.git"
BRANCH="main"

log_info "Starting DDoS SDN Deployment on Ubuntu 24.04"

# Update system
log_info "Updating system packages..."
apt-get update && apt-get upgrade -y

# Install Docker
log_info "Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    log_success "Docker installed"
else
    log_info "Docker already installed"
fi

# Install Docker Compose (v2 plugin)
log_info "Installing Docker Compose..."
if ! docker compose version &> /dev/null; then
    # Install docker-compose-plugin for Docker Compose v2
    apt-get install -y docker-compose-plugin
    log_success "Docker Compose v2 installed"
else
    log_info "Docker Compose already installed"
fi

# Install Python 3.12 (default on Ubuntu 24.04) and venv
log_info "Installing Python 3.12..."
apt-get install -y python3.12 python3.12-venv python3.12-dev python3-pip

# Install system dependencies
log_info "Installing system dependencies..."
apt-get install -y \
    openvswitch-switch \
    iproute2 \
    net-tools \
    iperf3 \
    tcpdump \
    curl \
    git \
    make \
    gcc \
    g++ \
    libpq-dev \
    prometheus-node-exporter \
    protobuf-compiler

# Create project directory
log_info "Creating project directory at $PROJECT_DIR..."
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# Clone repository (or copy from local)
if [[ -d ".git" ]]; then
    log_info "Repository exists, pulling latest..."
    git pull origin $BRANCH
else
    log_info "Cloning repository..."
    # For local development, copy files instead:
    # cp -r /path/to/local/project/* $PROJECT_DIR/
    git clone -b $BRANCH $REPO_URL .
fi

# Handle case where repo clones into subdirectory
if [[ -d "DDoS-Attack-Detection-and-Mitigation-main" ]]; then
    log_info "Repository cloned into subdirectory, moving files..."
    mv DDoS-Attack-Detection-and-Mitigation-main/* .
    mv DDoS-Attack-Detection-and-Mitigation-main/.* . 2>/dev/null || true
    rmdir DDoS-Attack-Detection-and-Mitigation-main
fi

# Create necessary directories
log_info "Creating data directories..."
mkdir -p $PROJECT_DIR/{models,data,logs,config}
mkdir -p /var/log/faucet /var/log/ml-service /var/log/ml-bridge
mkdir -p /etc/faucet/acls /etc/gauge

# Set permissions
chmod -R 755 $PROJECT_DIR
chown -R $SUDO_USER:$SUDO_USER $PROJECT_DIR 2>/dev/null || true

# Copy configuration files
log_info "Setting up configuration..."
cp $PROJECT_DIR/faucet_config/faucet.yaml /etc/faucet/faucet.yaml
cp $PROJECT_DIR/gauge_config/gauge.yaml /etc/gauge/gauge.yaml
# Don't copy config.ini to itself - it's already in place

# Create .env file for ML service
log_info "Creating environment file..."
cat > $PROJECT_DIR/.env <<EOF
SERVICE_HOST=0.0.0.0
SERVICE_PORT=8080
GRPC_PORT=50051
LOG_LEVEL=INFO
MODEL_DIR=$PROJECT_DIR/models
DEFAULT_MODEL=RandomForest
DATASET_PATH=$PROJECT_DIR/data/FlowStatsfile.csv
FAUCET_HOST=localhost
FAUCET_REST_PORT=9302
GAUGE_PROMETHEUS_PORT=9303
FAUCET_ACL_NAME=block-malicious
STATS_POLL_INTERVAL=10
DDOS_THRESHOLD_PERCENT=20.0
MITIGATION_COOLDOWN=300
METRICS_ENABLED=true
METRICS_PORT=9090
EOF

# Build and start Docker containers
log_info "Building Docker images..."
cd $PROJECT_DIR/docker
docker compose build

log_info "Starting services..."
docker compose up -d

# Wait for services to be healthy
log_info "Waiting for services to start..."
sleep 30

# Check service health
log_info "Checking service health..."
services=("faucet" "prometheus" "pushgateway" "grafana" "ml-service" "ml-bridge")
for service in "${services[@]}"; do
    if docker compose ps | grep -q "$service.*Up"; then
        log_success "$service is running"
    else
        log_warning "$service may not be running properly"
        docker compose logs $service | tail -20
    fi
done

# Setup systemd services for auto-start
log_info "Setting up systemd services..."
cat > /etc/systemd/system/ddos-sdn.service <<EOF
[Unit]
Description=DDoS SDN Detection & Mitigation
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$PROJECT_DIR/docker
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ddos-sdn.service

# Configure Open vSwitch
log_info "Configuring Open vSwitch..."
systemctl enable openvswitch-switch
systemctl start openvswitch-switch

# Create Mininet network script
log_info "Creating Mininet startup script..."
cat > $PROJECT_DIR/start_mininet.sh <<'MININET_EOF'
#!/bin/bash
# Start Mininet topology for testing

cd /opt/ddos-sdn/mininet
sudo python3 mininet_topology.py
MININET_EOF

chmod +x $PROJECT_DIR/start_mininet.sh

# Create test script
log_info "Creating test script..."
cat > $PROJECT_DIR/test_deployment.sh <<'TEST_EOF'
#!/bin/bash
# Test deployment

echo "Testing DDoS SDN Deployment..."
echo "================================"

# Test Faucet
echo -n "Faucet (port 9302): "
curl -s http://localhost:9302/metrics | head -1 && echo "OK" || echo "FAIL"

# Test Gauge
echo -n "Gauge (port 9303): "
curl -s http://localhost:9303/metrics | head -1 && echo "OK" || echo "FAIL"

# Test Prometheus
echo -n "Prometheus (port 9090): "
curl -s http://localhost:9090/-/healthy && echo "OK" || echo "FAIL"

# Test ML Service REST
echo -n "ML Service REST (port 8080): "
curl -s http://localhost:8080/health && echo "OK" || echo "FAIL"

# Test ML Service gRPC
echo -n "ML Service gRPC (port 50051): "
python3 -c "
import grpc
import sys
try:
    channel = grpc.insecure_channel('localhost:50051')
    grpc.channel_ready_future(channel).result(timeout=5)
    print('OK')
except:
    print('FAIL')
"

# Test Grafana
echo -n "Grafana (port 3000): "
curl -s http://localhost:3000/api/health | grep -q "ok" && echo "OK" || echo "FAIL"

echo "================================"
echo "Test complete"
TEST_EOF

chmod +x $PROJECT_DIR/test_deployment.sh

# Create model training script
log_info "Creating model training script..."
cat > $PROJECT_DIR/train_model.sh <<'TRAIN_EOF'
#!/bin/bash
# Train ML model

cd /opt/ddos-sdn
docker compose exec ml-service python -c "
import pandas as pd
from ml_service.model import ModelManager
from ml_service.config import settings
from pathlib import Path

model_manager = ModelManager(settings.model_dir)
df = pd.read_csv(settings.dataset_path)
print(f'Training on {len(df)} samples...')
metadata = model_manager.train_model('RandomForest', df)
print(f'Accuracy: {metadata[\"accuracy\"]:.4f}')
print('Training complete!')
"
TRAIN_EOF

chmod +x $PROJECT_DIR/train_model.sh

# Final status
log_success "Deployment completed!"
echo ""
echo "======================================"
echo "DDoS SDN Detection & Mitigation"
echo "======================================"
echo ""
echo "Services:"
echo "  - Faucet Controller:    http://localhost:9302"
echo "  - Gauge Metrics:        http://localhost:9303"
echo "  - Prometheus:           http://localhost:9090"
echo "  - Grafana:              http://localhost:3000 (admin/admin)"
echo "  - ML Service REST:      http://localhost:8080"
echo "  - ML Service gRPC:      localhost:50051"
echo "  - ML Service Metrics:   http://localhost:9092"
echo "  - Pushgateway:          http://localhost:9091"
echo ""
echo "Commands:"
echo "  - Test deployment:      $PROJECT_DIR/test_deployment.sh"
echo "  - Train model:          $PROJECT_DIR/train_model.sh"
echo "  - Start Mininet:        $PROJECT_DIR/start_mininet.sh"
echo "  - View logs:            cd $PROJECT_DIR/docker && docker compose logs -f"
echo "  - Stop services:        cd $PROJECT_DIR/docker && docker compose down"
echo "  - Restart services:     systemctl restart ddos-sdn"
echo ""
echo "Configuration:"
echo "  - Faucet config:        /etc/faucet/faucet.yaml"
echo "  - Gauge config:         /etc/gauge/gauge.yaml"
echo "  - ML Service config:    $PROJECT_DIR/.env"
echo "  - Models directory:     $PROJECT_DIR/models"
echo "  - Data directory:       $PROJECT_DIR/data"
echo ""
echo "Next steps:"
echo "  1. Place your dataset at $PROJECT_DIR/data/FlowStatsfile.csv"
echo "  2. Run training: $PROJECT_DIR/train_model.sh"
echo "  3. Start Mininet topology: $PROJECT_DIR/start_mininet.sh"
echo "  4. Access Grafana dashboard at http://localhost:3000"
echo ""