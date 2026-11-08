# Faucet Controller Migration Guide

## Kiến trúc mới: Hybrid Faucet + ML Service

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MININET TOPOLOGY                             │
│  6 Switches (s1-s6) + 18 Hosts (h1-h18)                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ OpenFlow 1.3
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │   FAUCET    │ │   FAUCET    │ │   FAUCET    │
    │ Controller  │ │ Controller  │ │ Controller  │
    │  (Primary)  │ │  (Backup)   │ │  (Backup)   │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                    ┌──────┴──────┐
                    ▼           ▼
           ┌─────────────┐ ┌─────────────┐
           │  GAUGE      │ │  ML SERVICE │
           │ (Metrics)   │ │  (Python)   │
           │ Prometheus  │ │  - Train    │
           └──────┬──────┘ │  - Predict  │
                  │       │  - Mitigate │
                  │       └──────┬──────┘
                  │              │ gRPC/REST
                  └──────────────┘
```

## Thành phần cần triển khai:

1. **Faucet Config** (`faucet_config/`) - YAML cho topology, VLAN, ACL
2. **Gauge Config** (`gauge_config/`) - Prometheus metrics export
3. **ML Service** (`ml_service/`) - gRPC/FastAPI server cho detection
4. **Faucet-ML Bridge** (`integration/`) - Poll stats → ML → Push ACL
5. **Docker Compose** (`docker/`) - Orchestration
6. **Deployment Scripts** (`deploy/`) - Ubuntu VM setup