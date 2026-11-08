#!/bin/bash
# Train ML model - Run from project root

set -e

echo "======================================"
echo "Training DDoS Detection Models"
echo "======================================"

# Check if dataset exists
if [ ! -f "data/FlowStatsfile.csv" ]; then
    echo "Dataset not found! Generating first..."
    python scripts/generate_dataset.py --benign 50000 --ddos 50000 --output data/FlowStatsfile.csv
fi

# Train using Docker (recommended)
if command -v docker-compose &> /dev/null && [ -f "docker/docker-compose.yml" ]; then
    echo "Training via Docker..."
    cd docker
    docker-compose exec ml-service python -m ml_service.train --all
    cd ..
else
    # Train locally
    echo "Training locally..."
    python -c "
import sys
sys.path.insert(0, '.')
from ml_service.train import train_all_models
from ml_service.config import settings
train_all_models(settings.dataset_path, settings.model_dir)
"
fi

echo ""
echo "======================================"
echo "Training complete!"
echo "======================================"
echo "Models saved to: ./models/"
echo ""
echo "To evaluate a specific model:"
echo "  python -m ml_service.train --model RandomForest --evaluate"