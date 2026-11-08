# DDoS Attack Detection and Mitigation with Faucet SDN Controller

A complete SDN-based DDoS detection and mitigation system using **Faucet Controller** (OpenFlow 1.3), **ML-based detection** (Random Forest, KNN, Decision Tree, etc.), and **Gauge/Prometheus** for telemetry.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DDoS SDN Detection & Mitigation                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                │
│  │   Mininet    │────▶│    Faucet    │────▶│    Gauge     │                │
│  │  (6 Switches, │     │  Controller  │     │  (Metrics)   │                │
│  │  18 Hosts)   │     │  (OpenFlow)  │     │              │                │
│  └──────────────┘     └──────────────┘     └──────┬───────┘                │
│                                                   │                        │
│                          ┌────────────────────────┘                        │
│                          ▼                                                 │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                │
│  │  Prometheus  │◀───▶│  ML Service  │────▶│    Faucet    │                │
│  │  (Storage)   │     │  (Detection) │     │   (ACL/Meter)│                │
│  └──────────────┘     └──────────────┘     └──────────────┘                │
│         │                     │                      ▲                       │
│         ▼                     ▼                      │                       │
│  ┌──────────────┐     ┌──────────────┐              │                       │
│  │   Grafana    │     │  gRPC/REST   │──────────────┘                       │
│  │  (Dashboards)│     │    API       │                                        │
│  └──────────────┘     └──────────────┘                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| **SDN Controller** | Faucet (Ryu-based) | OpenFlow 1.3 switch management |
| **Telemetry** | Gauge + Prometheus | Flow/port/meter statistics export |
| **ML Detection** | scikit-learn + FastAPI/gRPC | DDoS classification (6 algorithms) |
| **Mitigation** | Faucet ACLs + Meters | Port blocking, rate limiting |
| **Visualization** | Grafana | Real-time dashboards |
| **Network Emu** | Mininet | 6-switch, 18-host topology |

## Quick Start (Ubuntu VM)

### Prerequisites
- Ubuntu 20.04/22.04 LTS
- 4GB+ RAM, 2+ vCPUs
- Docker & Docker Compose

### One-Command Deployment

```bash
# Clone repository
git clone <your-repo-url>
cd DDoS-Attack-Detection-and-Mitigation-main

# Run deployment script
sudo bash deploy/install_ubuntu.sh
```

### Manual Deployment

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sh

# 2. Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 3. Start services
cd docker
docker-compose up -d --build

# 4. Verify
docker-compose ps
```

## Service Endpoints

| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana** | http://localhost:3000 | admin / admin |
| **Prometheus** | http://localhost:9090 | - |
| **Faucet Metrics** | http://localhost:9302/metrics | - |
| **Gauge Metrics** | http://localhost:9303/metrics | - |
| **ML Service REST** | http://localhost:8080 | - |
| **ML Service gRPC** | localhost:50051 | - |
| **Pushgateway** | http://localhost:9091 | - |

## ML Service API

### Health Check
```bash
curl http://localhost:8080/health
```

### Predict Flows (REST)
```bash
curl -X POST http://localhost:8080/predict \
  -H "Content-Type: application/json" \
  -d '{
    "flows": [{
      "timestamp": 1234567890,
      "datapath_id": 1,
      "flow_id": "flow_1",
      "ip_src": "10.0.0.5",
      "tp_src": 1234,
      "ip_dst": "10.0.0.1",
      "tp_dst": 80,
      "ip_proto": 6,
      "packet_count": 1000,
      "byte_count": 64000,
      "flow_duration_sec": 10,
      "packet_count_per_second": 100,
      "byte_count_per_second": 6400
    }],
    "switch_id": "s1"
  }'
```

### Train Model
```bash
curl -X POST http://localhost:8080/train \
  -H "Content-Type: application/json" \
  -d '{"model_type": "RandomForest"}'
```

### Apply Mitigation
```bash
curl -X POST http://localhost:8080/mitigate \
  -H "Content-Type: application/json" \
  -d '{
    "action": "BLOCK_PORT",
    "switch_id": "s1",
    "port_number": 1,
    "reason": "DDoS detected",
    "duration_seconds": 120
  }'
```

### gRPC API (Python)
```python
import grpc
import ddos_pb2
import ddos_pb2_grpc

channel = grpc.insecure_channel('localhost:50051')
stub = ddos_pb2_grpc.DDoSServiceStub(channel)

# Predict
request = ddos_pb2.FlowBatch(
    flows=[ddos_pb2.FlowFeatures(
        timestamp=1234567890,
        datapath_id=1,
        flow_id="flow_1",
        ip_src="10.0.0.5",
        tp_src=1234,
        ip_dst="10.0.0.1",
        tp_dst=80,
        ip_proto=6,
        packet_count=1000,
        byte_count=64000,
        flow_duration_sec=10,
        packet_count_per_second=100,
        byte_count_per_second=6400
    )],
    switch_id="s1"
)
response = stub.Predict(request)
print(f"DDoS: {response.ddos_count}/{response.total_flows} ({response.ddos_percentage:.1f}%)")
```

## Model Training

```bash
# Train all models
docker-compose exec ml-service python -m ml_service.train --all

# Train specific model
docker-compose exec ml-service python -m ml_service.train --model RandomForest

# Evaluate model
docker-compose exec ml-service python -m ml_service.train --model RandomForest --evaluate
```

## Mininet Topology

Start the 6-switch, 18-host test topology:

```bash
# On host (requires privileged)
sudo python3 mininet/mininet_topology.py
```

This creates:
- **6 Open vSwitch switches** (s1-s6) with dp_id 0x1-0x6
- **18 hosts** (h1-h18) across 5 VLANs (100-500)
- **Inter-switch links** with all VLANs tagged
- **OpenFlow 1.3** connectivity to Faucet on port 6653

### Generate Test Traffic

```bash
# From Mininet CLI
mininet> h1 iperf3 -s &
mininet> h5 iperf3 -c 10.0.0.1 -t 30 -P 10

# Or use the traffic generator
mininet> h5 python3 -m mininet.traffic_generator --target 10.0.0.1 --duration 60
```

## Configuration

### Faucet Configuration (`faucet_config/faucet.yaml`)
- 6 datapaths (switches) with dp_id 0x1-0x6
- 5 VLANs (100-500) with inter-VLAN routing
- ACLs for DDoS mitigation (`block-malicious`, `protect-web-server`)
- Meters for rate limiting (ICMP, HTTP, UDP, general)

### Gauge Configuration (`gauge_config/gauge.yaml`)
- Prometheus export on port 9303
- 10-second polling interval
- Metrics: port stats, flow table, flow matches, meter stats

### ML Service Configuration (`.env`)
```bash
SERVICE_HOST=0.0.0.0
SERVICE_PORT=8080
GRPC_PORT=50051
MODEL_DIR=/app/models
DEFAULT_MODEL=RandomForest
DATASET_PATH=/app/data/FlowStatsfile.csv
FAUCET_HOST=faucet
FAUCET_REST_PORT=9302
GAUGE_PROMETHEUS_PORT=9303
STATS_POLL_INTERVAL=10
DDOS_THRESHOLD_PERCENT=20.0
MITIGATION_COOLDOWN=300
```

## Grafana Dashboards

Access Grafana at http://localhost:3000 (admin/admin)

Pre-configured dashboard: **DDoS SDN Detection & Mitigation**
- DDoS Detection Rate (%)
- Attacks Detected (per minute)
- Active Switches
- Mitigation Actions Rate
- Prediction Latency (p95, p99)
- Flow Packet Rate per Switch
- Port RX Byte Rate
- Port Dropped Packets Rate
- Total Port Blocks

## Mitigation Actions

The system supports three mitigation actions:

| Action | Description | Faucet Mechanism |
|--------|-------------|------------------|
| **BLOCK_PORT** | Block all traffic on a port | ACL with `allow: false` |
| **UNBLOCK_PORT** | Restore traffic on a port | Remove/Update ACL rule |
| **RATE_LIMIT** | Apply rate limiting | Faucet Meters (KBPS/PKTPS) |

### Auto-Mitigation Flow
1. **Gauge** collects flow stats every 10s → Prometheus
2. **ML Bridge** polls Prometheus → extracts flow features
3. **ML Service** predicts DDoS/benign for each flow
4. **Threshold Check**: If >20% flows are DDoS on a switch
5. **Mitigation**: Apply ACL block on victim port
6. **Cooldown**: 300s before next mitigation on same port

## Supported ML Algorithms

| Algorithm | Parameters | Use Case |
|-----------|------------|----------|
| **RandomForest** | n_estimators=100, max_depth=10 | Default, balanced accuracy |
| **KNN** | n_neighbors=5, weights=distance | Fast inference |
| **DecisionTree** | max_depth=10, entropy | Interpretable |
| **LogisticRegression** | solver=liblinear, C=1.0 | Linear baseline |
| **NaiveBayes** | var_smoothing=1e-9 | Fast, probabilistic |
| **SVM** | kernel=rbf, probability=True | Non-linear boundary |

## Project Structure

```
DDoS-Attack-Detection-and-Mitigation-main/
├── config.ini                    # Centralized configuration
├── config_loader.py              # Config loader with dataclasses
├── common_utils.py               # Shared utilities (ML, matplotlib)
├── faucet_config/
│   └── faucet.yaml              # Faucet controller config
├── gauge_config/
│   └── gauge.yaml               # Gauge telemetry config
├── ml_service/
│   ├── config.py                # Pydantic settings
│   ├── model.py                 # ML models (6 algorithms)
│   ├── faucet_client.py         # Faucet/Gauge client
│   ├── grpc_service.py          # gRPC service implementation
│   ├── server.py                # FastAPI REST API
│   ├── train.py                 # Training script
│   ├── ddos.proto               # gRPC protobuf definition
│   └── requirements.txt
├── integration/
│   └── faucet_ml_bridge.py      # Gauge→ML→Faucet bridge
├── mininet/
│   ├── mininet_topology.py      # 6-switch, 18-host topology
│   └── traffic_generator.py     # DDoS traffic generator
├── docker/
│   ├── docker-compose.yml       # Full stack orchestration
│   ├── Dockerfile.ml            # ML service container
│   ├── Dockerfile.mininet       # Mininet container
│   ├── prometheus.yml           # Prometheus config
│   └── grafana/                 # Grafana provisioning
├── deploy/
│   └── install_ubuntu.sh        # Ubuntu deployment script
└── README.md
```

## Troubleshooting

### Services not starting
```bash
# Check logs
docker-compose logs -f faucet
docker-compose logs -f ml-service
docker-compose logs -f ml-bridge

# Restart
docker-compose restart
```

### Faucet not connecting to switches
- Verify Open vSwitch is running: `systemctl status openvswitch-switch`
- Check dp_id matches: `ovs-vsctl get bridge s1 other-config:datapath-id`
- Ensure port 6653 is open

### ML Service not detecting attacks
- Verify Gauge metrics: `curl http://localhost:9303/metrics | grep of_flow`
- Check ML model is trained: `curl http://localhost:8080/model`
- Verify dataset exists at `/app/data/FlowStatsfile.csv`

### Mininet permission errors
- Run with sudo: `sudo python3 mininet_topology.py`
- Or add user to docker group: `sudo usermod -aG docker $USER`

## License

MIT License - See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## Support

For issues and questions, please open a GitHub issue.